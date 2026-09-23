using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepNative;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace Deep.Protocol.Tests.ApplicationCore;

public sealed class ApplicationCoreVerificationTests
{
    [Fact]
    public void PublicDecoders_ReturnExplicitParsedTypes_AndDmc2PayloadIsNotAuthoritative()
    {
        var decoders = typeof(ApplicationCoreCodec).GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Where(method => method.Name.StartsWith("Decode", StringComparison.Ordinal))
            .Where(method => method.Name is "DecodeDid1" or "DecodeDeepIdText" or "DecodeDab1" or
                "DecodeDmd1" or "DecodeDca1" or "DecodeDao1" or "DecodeDmc2")
            .ToArray();

        Assert.NotEmpty(decoders);
        Assert.All(decoders, method => Assert.StartsWith("Parsed", method.ReturnType.Name));
        Assert.Null(typeof(ParsedDmc2).GetProperty("Payload", BindingFlags.Public | BindingFlags.Instance));
        Assert.NotNull(typeof(VerifiedDmc2).GetProperty("Payload", BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(VerifiedDab1).GetConstructors());
        Assert.Empty(typeof(VerifiedDmd1).GetConstructors());
        Assert.Empty(typeof(VerifiedDca1).GetConstructors());
        Assert.Empty(typeof(VerifiedDmc2).GetConstructors());
        Assert.Empty(typeof(VerifiedDpe2Envelope).GetConstructors());
        Assert.Empty(typeof(Dpe2AuthenticationOutput).GetConstructors());
    }

    [Fact]
    public void Verifier_ClosesDpaDrsDpdAndAllApplicationSignatures()
    {
        var fixture = VerifiedFixture.Create();
        var binding = fixture.AuthorAndVerifyDab1(0, new byte[32]);
        var directory = fixture.AuthorAndVerifyDmd1(1, new byte[32]);
        var authorization = fixture.AuthorAndVerifyDca1(binding, directory);

        Assert.Same(fixture.Identity, binding.Identity);
        Assert.Same(fixture.Identity, directory.Identity);
        Assert.Same(binding, authorization.Binding);
        Assert.Same(directory, authorization.Directory);
    }

    [Fact]
    public void Dab2_RequiresExactAccountClosureAndBothRootSignatures()
    {
        var fixture = VerifiedFixture.Create();
        var pqPublicKey = ApplicationCoreFixture.Bytes(1952, 0x71);
        var pqSignature = ApplicationCoreFixture.Bytes(3309, 0x72);
        var did = DeepIdV2Codec.AuthorDid2(
            fixture.AddressKey.PublicKey, pqPublicKey,
            ApplicationCoreFixture.Bytes(16, 0x73));
        var realm = DeepIdV2Codec.DeriveIdentityRealmId(
            fixture.Network, VerifiedFixture.DeploymentProfileId);
        var dpa = fixture.Account.Certificate;
        var reference = ApplicationCoreCodec.CreateArtifactReference(
            (ushort)dpa.ArtifactType, checked((uint)dpa.CanonicalBytes.Length),
            dpa.CanonicalHash.Span);

        ParsedDab2 Author(byte[] edSignature, byte[] pqSignatureValue, byte[] accountSignature) =>
            DeepIdV2Codec.AuthorDab2(did.RecordHash.Span, realm, 0, new byte[32],
                fixture.AccountId, 1, reference,
                edSignature, pqSignatureValue, accountSignature);

        var unsigned = Author(ApplicationCoreFixture.Bytes(64, 0x74), pqSignature,
            ApplicationCoreFixture.Bytes(64, 0x75));
        var ed = PublicKeyAuth.SignDetached(
            unsigned.RootEd25519SignatureInput.ToArray(), fixture.AddressKey.PrivateKey);
        var account = PublicKeyAuth.SignDetached(
            unsigned.AccountSignatureInput.ToArray(), fixture.AccountKey.PrivateKey);
        var valid = Author(ed, pqSignature, account);
        var pqVerifier = new ExactTestPqVerifier(
            pqPublicKey, valid.RootMlDsa65SignatureInput.ToArray(), pqSignature);
        var verified = DeepIdV2Verifier.VerifyDab2(valid, did, fixture.Identity,
            VerifiedFixture.DeploymentProfileId, pqVerifier);
        Assert.Same(valid, verified.Record);
        Assert.Same(did, verified.DeepId);

        var directory = fixture.AuthorAndVerifyDmd1(1, new byte[32]);
        ParsedDca1V2 AuthorContact(ReadOnlySpan<byte> accountSignature,
            ReadOnlySpan<byte> exactDidHash, ApplicationArtifactReference dabReference) =>
            DeepIdV2ContactAuthorizationCodec.Author(fixture.Network, fixture.AccountId,
                reference, directory.Record.DirectoryGeneration,
                directory.Record.RecordHash.Span,
                ApplicationCoreFixture.Bytes(32, 0x77), fixture.DeviceId,
                3, 100, 10, 20, accountSignature, exactDidHash, dabReference);
        var dab2Reference = DeepIdV2Codec.CreateDab2ArtifactReference(valid);
        var unsignedContact = AuthorContact(ApplicationCoreFixture.Bytes(64, 0x76),
            did.RecordHash.Span, dab2Reference);
        var contactSignature = PublicKeyAuth.SignDetached(
            unsignedContact.SignatureInput.ToArray(), fixture.AccountKey.PrivateKey);
        var contact = AuthorContact(contactSignature, did.RecordHash.Span, dab2Reference);
        var contactVerified = DeepIdV2ContactAuthorizationCodec.Verify(contact, verified, directory);
        Assert.Same(verified, contactVerified.Binding);
        Assert.Same(directory, contactVerified.Directory);
        var oldVersion = contact.CanonicalBytes.ToArray();
        oldVersion[5] = 1;
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2ContactAuthorizationCodec.Decode(oldVersion));
        var oldSuite = contact.CanonicalBytes.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(oldSuite.AsSpan(6, 2), 0x0201);
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2ContactAuthorizationCodec.Decode(oldSuite));
        var oldBindingType = contact.CanonicalBytes.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(oldBindingType.AsSpan(435, 2),
            ApplicationCoreCodec.Dab1ArtifactTypeCode);
        Assert.Throws<ApplicationCoreFormatException>(() =>
            DeepIdV2ContactAuthorizationCodec.Decode(oldBindingType));
        Assert.Same(contactVerified,
            DeepIdV2ContactAuthorizationCodec.RequireCurrentlyAuthoritative(contactVerified, 10));
        AssertVerificationFailure(() => DeepIdV2ContactAuthorizationCodec.Verify(
            AuthorContact(ApplicationCoreFixture.Bytes(64, 0x78), did.RecordHash.Span,
                dab2Reference), verified, directory));
        AssertVerificationFailure(() => DeepIdV2ContactAuthorizationCodec.Verify(
            AuthorContact(contactSignature, ApplicationCoreFixture.Bytes(32, 0x79),
                dab2Reference), verified, directory));
        Assert.Throws<ArgumentException>(() => AuthorContact(contactSignature,
            did.RecordHash.Span, ApplicationCoreCodec.CreateArtifactReference(
                ApplicationCoreCodec.Dab1ArtifactTypeCode, 339, valid.RecordHash.Span)));
        AssertVerificationFailure(() =>
            DeepIdV2ContactAuthorizationCodec.RequireCurrentlyAuthoritative(contactVerified, 20));

        AssertVerificationFailure(() => DeepIdV2Verifier.VerifyDab2(valid, did,
            fixture.Identity, VerifiedFixture.DeploymentProfileId + 1, pqVerifier));
        AssertVerificationFailure(() => DeepIdV2Verifier.VerifyDab2(
            Author(ApplicationCoreFixture.Bytes(64, 0x76), pqSignature, account),
            did, fixture.Identity, VerifiedFixture.DeploymentProfileId, pqVerifier));
        AssertVerificationFailure(() => DeepIdV2Verifier.VerifyDab2(
            Author(ed, ApplicationCoreFixture.Bytes(3309, 0x77), account),
            did, fixture.Identity, VerifiedFixture.DeploymentProfileId, pqVerifier));
        AssertVerificationFailure(() => DeepIdV2Verifier.VerifyDab2(
            Author(ed, pqSignature, ApplicationCoreFixture.Bytes(64, 0x78)),
            did, fixture.Identity, VerifiedFixture.DeploymentProfileId, pqVerifier));
        AssertVerificationFailure(() => DeepIdV2Verifier.VerifyDab2(valid, did,
            fixture.Identity, VerifiedFixture.DeploymentProfileId,
            new ThrowingTestPqVerifier()));
    }

    private sealed class ExactTestPqVerifier(
        byte[] expectedPublicKey, byte[] expectedMessage, byte[] expectedSignature)
        : IDeepMlDsa65Verifier
    {
        public bool Verify(ReadOnlySpan<byte> publicKey1952, ReadOnlySpan<byte> message,
            ReadOnlySpan<byte> context, ReadOnlySpan<byte> signature3309) =>
            publicKey1952.SequenceEqual(expectedPublicKey) &&
            message.SequenceEqual(expectedMessage) &&
            context.SequenceEqual("Deep/DAB2/V2/root"u8) &&
            signature3309.SequenceEqual(expectedSignature);
    }

    private sealed class ThrowingTestPqVerifier : IDeepMlDsa65Verifier
    {
        public bool Verify(ReadOnlySpan<byte> publicKey1952, ReadOnlySpan<byte> message,
            ReadOnlySpan<byte> context, ReadOnlySpan<byte> signature3309) =>
            throw new PlatformNotSupportedException("test-only unavailable provider");
    }

    [Fact]
    public void Dab2_RealNativeHybridSignaturesCloseOverExactDidAndAccount()
    {
        if (!OperatingSystem.IsWindows() ||
            RuntimeInformation.ProcessArchitecture is not (Architecture.X64 or Architecture.Arm64))
            return;

        var fixture = VerifiedFixture.Create();
        var seed = Enumerable.Range(0, 32).Select(value => (byte)(value + 1)).ToArray();
        using var pq = DeepMlDsa65NativeProvider.LoadCandidateForCurrentProcess();
        try
        {
            var did = DeepIdV2Codec.AuthorDid2(fixture.AddressKey.PublicKey,
                pq.DerivePublicKey(seed), ApplicationCoreFixture.Bytes(16, 0x79));
            var account = fixture.Account.Certificate;
            var reference = ApplicationCoreCodec.CreateArtifactReference(
                (ushort)account.ArtifactType, checked((uint)account.CanonicalBytes.Length),
                account.CanonicalHash.Span);
            var realm = DeepIdV2Codec.DeriveIdentityRealmId(
                fixture.Network, VerifiedFixture.DeploymentProfileId);
            ParsedDab2 AuthorAt(ulong generation, byte[] predecessor,
                byte[] ed, byte[] pqSignature, byte[] accountSignature) =>
                DeepIdV2Codec.AuthorDab2(did.RecordHash.Span, realm, generation, predecessor,
                    fixture.AccountId, 1, reference, ed, pqSignature, accountSignature);
            ParsedDab2 Author(byte[] ed, byte[] pqSignature, byte[] accountSignature) =>
                AuthorAt(0, new byte[32], ed, pqSignature, accountSignature);
            var unsigned = Author(ApplicationCoreFixture.Bytes(64, 0x7a),
                ApplicationCoreFixture.Bytes(3309, 0x7b), ApplicationCoreFixture.Bytes(64, 0x7c));
            var edSignature = PublicKeyAuth.SignDetached(
                unsigned.RootEd25519SignatureInput.ToArray(), fixture.AddressKey.PrivateKey);
            var pqSignature = pq.Sign(seed, "Deep/DAB2/V2/root"u8,
                unsigned.RootMlDsa65SignatureInput.Span);
            var accountSignature = PublicKeyAuth.SignDetached(
                unsigned.AccountSignatureInput.ToArray(), fixture.AccountKey.PrivateKey);
            var signed = Author(edSignature, pqSignature, accountSignature);
            var verified = DeepIdV2Verifier.VerifyDab2(signed, did, fixture.Identity,
                VerifiedFixture.DeploymentProfileId, pq);
            Assert.Same(signed, verified.Record);
            var genesis = DeepIdV2Verifier.StartDab2Lineage(verified);
            Assert.Equal(ApplicationLineageDisposition.AcceptedGenesis, genesis.Disposition);
            Assert.Equal(ApplicationLineageDisposition.ExactReplay,
                DeepIdV2Verifier.PrepareDab2Transition(genesis.Next, verified).Disposition);

            var successorUnsigned = AuthorAt(1, signed.RecordHash.ToArray(),
                ApplicationCoreFixture.Bytes(64, 0x7a),
                ApplicationCoreFixture.Bytes(3309, 0x7b),
                ApplicationCoreFixture.Bytes(64, 0x7c));
            ParsedDab2 SignSuccessor() => AuthorAt(1, signed.RecordHash.ToArray(),
                PublicKeyAuth.SignDetached(successorUnsigned.RootEd25519SignatureInput.ToArray(),
                    fixture.AddressKey.PrivateKey),
                pq.Sign(seed, "Deep/DAB2/V2/root"u8,
                    successorUnsigned.RootMlDsa65SignatureInput.Span),
                PublicKeyAuth.SignDetached(successorUnsigned.AccountSignatureInput.ToArray(),
                    fixture.AccountKey.PrivateKey));
            var successor = DeepIdV2Verifier.VerifyDab2(SignSuccessor(), did, fixture.Identity,
                VerifiedFixture.DeploymentProfileId, pq);
            var advanced = DeepIdV2Verifier.PrepareDab2Transition(genesis.Next, successor);
            Assert.Equal(ApplicationLineageDisposition.AcceptedSuccessor, advanced.Disposition);
            var competing = DeepIdV2Verifier.VerifyDab2(SignSuccessor(), did, fixture.Identity,
                VerifiedFixture.DeploymentProfileId, pq);
            var fork = DeepIdV2Verifier.PrepareDab2Transition(advanced.Next, competing);
            Assert.Equal(ApplicationLineageDisposition.ForkLatched, fork.Disposition);
            Assert.True(fork.Next.ForkLatched);
            AssertLineageFailure(() => DeepIdV2Verifier.PrepareDab2Transition(fork.Next, successor));
            AssertLineageFailure(() => DeepIdV2Verifier.PrepareDab2Transition(advanced.Next, verified));

            var substituted = pqSignature.ToArray();
            substituted[^1] ^= 1;
            AssertVerificationFailure(() => DeepIdV2Verifier.VerifyDab2(
                Author(edSignature, substituted, accountSignature), did, fixture.Identity,
                VerifiedFixture.DeploymentProfileId, pq));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    [Fact]
    public void Dab2_SafetyNumberIsSymmetricAndCommitsToPqGenesisRoot()
    {
        static Dab2LineageState Build(VerifiedFixture fixture, byte pqKeyStart)
        {
            var pqPublicKey = ApplicationCoreFixture.Bytes(1952, pqKeyStart);
            var pqSignature = ApplicationCoreFixture.Bytes(3309, 0x81);
            var did = DeepIdV2Codec.AuthorDid2(fixture.AddressKey.PublicKey,
                pqPublicKey, ApplicationCoreFixture.Bytes(16, 0x82));
            var account = fixture.Account.Certificate;
            var reference = ApplicationCoreCodec.CreateArtifactReference(
                (ushort)account.ArtifactType, checked((uint)account.CanonicalBytes.Length),
                account.CanonicalHash.Span);
            var realm = DeepIdV2Codec.DeriveIdentityRealmId(
                fixture.Network, VerifiedFixture.DeploymentProfileId);
            ParsedDab2 Author(byte[] ed, byte[] accountSignature) =>
                DeepIdV2Codec.AuthorDab2(did.RecordHash.Span, realm, 0, new byte[32],
                    fixture.AccountId, 1, reference, ed, pqSignature, accountSignature);
            var unsigned = Author(ApplicationCoreFixture.Bytes(64, 0x83),
                ApplicationCoreFixture.Bytes(64, 0x84));
            var signed = Author(
                PublicKeyAuth.SignDetached(unsigned.RootEd25519SignatureInput.ToArray(),
                    fixture.AddressKey.PrivateKey),
                PublicKeyAuth.SignDetached(unsigned.AccountSignatureInput.ToArray(),
                    fixture.AccountKey.PrivateKey));
            var verifier = new ExactTestPqVerifier(
                pqPublicKey, signed.RootMlDsa65SignatureInput.ToArray(), pqSignature);
            var verified = DeepIdV2Verifier.VerifyDab2(signed, did, fixture.Identity,
                VerifiedFixture.DeploymentProfileId, verifier);
            return DeepIdV2Verifier.StartDab2Lineage(verified).Next;
        }

        var alice = VerifiedFixture.Create(accountValue: 0x22, deviceValue: 0x33);
        var bob = VerifiedFixture.Create(accountValue: 0x44, deviceValue: 0x55);
        var aliceOriginal = Build(alice, 0x85);
        var aliceChangedPqRoot = Build(alice, 0x86);
        var bobBinding = Build(bob, 0x87);
        var original = DeepIdV2Verifier.ComputeContactSafetyNumber(aliceOriginal, bobBinding);
        Assert.Equal(original,
            DeepIdV2Verifier.ComputeContactSafetyNumber(bobBinding, aliceOriginal));
        Assert.NotEqual(original,
            DeepIdV2Verifier.ComputeContactSafetyNumber(aliceChangedPqRoot, bobBinding));
        AssertVerificationFailure(() =>
            DeepIdV2Verifier.ComputeContactSafetyNumber(aliceOriginal, aliceChangedPqRoot));
        AssertLineageFailure(() => DeepIdV2Verifier.ComputeContactSafetyNumber(
            new Dab2LineageState(aliceOriginal.Head, forkLatched: true), bobBinding));
    }

    [Fact]
    public void ContactSafetyNumber_UsesSortedVerifiedDpa1HashesAndRejectsForks()
    {
        var alice = VerifiedFixture.Create(accountValue: 0x22, deviceValue: 0x33);
        var bob = VerifiedFixture.Create(accountValue: 0x44, deviceValue: 0x55);
        var aliceBinding = alice.AuthorAndVerifyDab1(0, new byte[32]);
        var bobBinding = bob.AuthorAndVerifyDab1(0, new byte[32]);
        var left = ApplicationCoreVerifier.StartDab1Lineage(aliceBinding).Next;
        var right = ApplicationCoreVerifier.StartDab1Lineage(bobBinding).Next;

        var actual = ApplicationCoreVerifier.ComputeContactSafetyNumber(left, right);
        Assert.Equal(actual,
            ApplicationCoreVerifier.ComputeContactSafetyNumber(right, left));

        var leftAccount = alice.Account.Certificate;
        var rightAccount = bob.Account.Certificate;
        var lower = leftAccount.CanonicalHash.Span.SequenceCompareTo(
            rightAccount.CanonicalHash.Span) < 0 ? leftAccount : rightAccount;
        var upper = ReferenceEquals(lower, leftAccount) ? rightAccount : leftAccount;
        var material = new byte[96];
        alice.Network.CopyTo(material, 0);
        lower.CanonicalHash.Span.CopyTo(material.AsSpan(16));
        BinaryPrimitives.WriteUInt64BigEndian(material.AsSpan(48),
            lower.AccountGeneration);
        upper.CanonicalHash.Span.CopyTo(material.AsSpan(56));
        BinaryPrimitives.WriteUInt64BigEndian(material.AsSpan(88),
            upper.AccountGeneration);
        var domain = Encoding.ASCII.GetBytes(
            "Deep/Application/V1/contact-safety-number");
        var input = new byte[domain.Length + 1 + 4 + material.Length];
        domain.CopyTo(input, 0);
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(domain.Length + 1),
            checked((uint)material.Length));
        material.CopyTo(input, domain.Length + 5);
        Assert.Equal(SHA256.HashData(input), actual);

        AssertVerificationFailure(() =>
            ApplicationCoreVerifier.ComputeContactSafetyNumber(left, left));
        AssertVerificationFailure(() =>
            ApplicationCoreVerifier.ComputeContactSafetyNumber(
                new Dab1LineageState(aliceBinding, forkLatched: true), right));
    }

    [Fact]
    public void ContactHelloEndpointBindings_RequireExactVerifiedIdentityAndSignedXur1()
    {
        var alice = VerifiedFixture.Create(accountValue: 0x22, deviceValue: 0x33);
        var bob = VerifiedFixture.Create(accountValue: 0x44, deviceValue: 0x55);
        var aliceBinding = ApplicationCoreVerifier.StartDab1Lineage(
            alice.AuthorAndVerifyDab1(0, new byte[32])).Next;
        var aliceDirectory = ApplicationCoreVerifier.StartDmd1Lineage(
            alice.AuthorAndVerifyDmd1(1, new byte[32])).Next;
        var bobBinding = ApplicationCoreVerifier.StartDab1Lineage(
            bob.AuthorAndVerifyDab1(0, new byte[32])).Next;
        var dab1Reference = ContactReference("DAB1",
            aliceBinding.Head.Record.RecordHash.Span);
        var safety = ApplicationCoreVerifier.ComputeContactSafetyNumber(
            aliceBinding, bobBinding);
        var device = alice.Identity.ActiveDevices[0].Certificate;
        var dpd1Reference = ContactReference("DPD1", device.CanonicalHash.Span);
        var fields = new ReadOnlyMemory<byte>[]
        {
            alice.Network, ApplicationCoreFixture.Bytes(32, 0x61),
            ApplicationCoreFixture.Bytes(32, 0x62), BigEndian64(0), new byte[32],
            ContactReference("PMT2", 0x63), ApplicationCoreFixture.Bytes(32, 0x64),
            ApplicationCoreFixture.Bytes(32, 0x65), ApplicationCoreFixture.Bytes(32, 0x66),
            new byte[] { 0, 7 }, BigEndian64(150), BigEndian64(500),
            alice.DeviceId, dpd1Reference, ApplicationCoreFixture.Bytes(64, 0x67)
        };
        var unsignedXur1 = ContactCodecValidation.AuthorRecord("XUR1", fields);
        fields[14] = PublicKeyAuth.SignDetached(
            unsignedXur1.SignatureInput.ToArray(), alice.DeviceKey.PrivateKey);
        var signedXur1 = ContactCodecValidation.AuthorRecord("XUR1", fields);

        ParsedDmc2 Hello(byte[] dab1, byte[] dmd1, byte[] safetyHash, byte[] xur1) =>
            ContactCodecValidation.AuthorDmc2(
                alice.Network, ApplicationCoreFixture.Bytes(32, 0x71),
                ApplicationCoreFixture.Bytes(32, 0x72), alice.AccountId,
                alice.DeviceId, 1, 200_000, 300_000, Dmc2Flags.None,
                ReadOnlySpan<byte>.Empty,
                ContactCodecValidation.CreateContactHelloPayload(
                    ApplicationCoreFixture.Bytes(32, 0x73), dab1, dmd1,
                    safetyHash, ContactPolicy.AllowRouteUpdates, xur1));

        var valid = Hello(dab1Reference, aliceDirectory.Head.Record.RecordHash.ToArray(),
            safety, signedXur1.CanonicalBytes.ToArray());
        ApplicationCoreVerifier.RequireContactHelloEndpointBindings(
            valid, aliceBinding, aliceDirectory, bobBinding);

        var wrongSafety = safety.ToArray();
        wrongSafety[0] ^= 1;
        AssertVerificationFailure(() => ApplicationCoreVerifier.RequireContactHelloEndpointBindings(
            Hello(dab1Reference, aliceDirectory.Head.Record.RecordHash.ToArray(),
                wrongSafety, signedXur1.CanonicalBytes.ToArray()),
            aliceBinding, aliceDirectory, bobBinding));
        var wrongDab1 = dab1Reference.ToArray();
        wrongDab1[^1] ^= 1;
        AssertVerificationFailure(() => ApplicationCoreVerifier.RequireContactHelloEndpointBindings(
            Hello(wrongDab1, aliceDirectory.Head.Record.RecordHash.ToArray(),
                safety, signedXur1.CanonicalBytes.ToArray()),
            aliceBinding, aliceDirectory, bobBinding));
        AssertVerificationFailure(() => ApplicationCoreVerifier.RequireContactHelloEndpointBindings(
            Hello(dab1Reference, ApplicationCoreFixture.Bytes(32, 0x74),
                safety, signedXur1.CanonicalBytes.ToArray()),
            aliceBinding, aliceDirectory, bobBinding));
        var wrongAuthorFields = fields.ToArray();
        wrongAuthorFields[12] = bob.DeviceId;
        var unsignedWrongAuthor = ContactCodecValidation.AuthorRecord("XUR1", wrongAuthorFields);
        wrongAuthorFields[14] = PublicKeyAuth.SignDetached(
            unsignedWrongAuthor.SignatureInput.ToArray(), alice.DeviceKey.PrivateKey);
        var wrongAuthor = ContactCodecValidation.AuthorRecord("XUR1", wrongAuthorFields);
        AssertVerificationFailure(() => ApplicationCoreVerifier.RequireContactHelloEndpointBindings(
            Hello(dab1Reference, aliceDirectory.Head.Record.RecordHash.ToArray(),
                safety, wrongAuthor.CanonicalBytes.ToArray()),
            aliceBinding, aliceDirectory, bobBinding));
        var badSignatureFields = fields.ToArray();
        badSignatureFields[14] = ApplicationCoreFixture.Bytes(64, 0x68);
        var badSignature = ContactCodecValidation.AuthorRecord("XUR1", badSignatureFields);
        Assert.Throws<ContactFormatException>(() =>
            ApplicationCoreVerifier.RequireContactHelloEndpointBindings(
                Hello(dab1Reference, aliceDirectory.Head.Record.RecordHash.ToArray(),
                    safety, badSignature.CanonicalBytes.ToArray()),
                aliceBinding, aliceDirectory, bobBinding));
    }

    private static byte[] BigEndian64(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] ContactReference(string magic, byte hashValue)
    {
        var bytes = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1);
        ApplicationCoreFixture.Bytes(32, hashValue).CopyTo(bytes, 6);
        return bytes;
    }

    private static byte[] ContactReference(string magic, ReadOnlySpan<byte> hash)
    {
        var bytes = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1);
        hash.CopyTo(bytes.AsSpan(6));
        return bytes;
    }

    [Fact]
    public void Verifier_RejectsSignatureAndExactClosureSubstitutions()
    {
        var fixture = VerifiedFixture.Create();
        var binding = fixture.AuthorAndVerifyDab1(0, new byte[32]);
        var directory = fixture.AuthorAndVerifyDmd1(1, new byte[32]);

        var badBindingBytes = binding.Record.CanonicalBytes.ToArray();
        badBindingBytes[ApplicationCoreFixture.FieldOffset(badBindingBytes, 8)] ^= 0x01;
        var badBinding = ApplicationCoreCodec.DecodeDab1(badBindingBytes);
        AssertVerificationFailure(() => ApplicationCoreVerifier.VerifyDab1(
            badBinding, fixture.DeepId, fixture.Identity, VerifiedFixture.DeploymentProfileId));

        var emptyClosure = ApplicationCoreVerifier.CreateIdentityClosure(
            fixture.Account, fixture.Revocations, []);
        AssertVerificationFailure(() => ApplicationCoreVerifier.VerifyDmd1(directory.Record, emptyClosure));

        var wrongPublisher = ApplicationCoreFixture.Bytes(32, 0xee);
        var badAuthorization = fixture.AuthorDca1(binding, directory, wrongPublisher);
        AssertVerificationFailure(() => ApplicationCoreVerifier.VerifyDca1(
            badAuthorization, binding, directory));
    }

    [Fact]
    public void Dab1Lineage_EnforcesSuccessorReplayAndPermanentForkLatch()
    {
        var fixture = VerifiedFixture.Create();
        var genesis = fixture.AuthorAndVerifyDab1(0, new byte[32]);
        var started = ApplicationCoreVerifier.StartDab1Lineage(genesis);
        var successor = fixture.AuthorAndVerifyDab1(1, genesis.Record.RecordHash.Span);
        var accepted = ApplicationCoreVerifier.PrepareDab1Transition(started.Next, successor);

        Assert.Equal(ApplicationLineageDisposition.AcceptedSuccessor, accepted.Disposition);
        Assert.Equal(ApplicationLineageDisposition.ExactReplay,
            ApplicationCoreVerifier.PrepareDab1Transition(accepted.Next, successor).Disposition);

        var alternate = VerifiedFixture.Create(fixture.AddressKey, accountValue: 0x91, deviceValue: 0x92);
        var conflicting = alternate.AuthorAndVerifyDab1(1, genesis.Record.RecordHash.Span);
        var fork = ApplicationCoreVerifier.PrepareDab1Transition(accepted.Next, conflicting);
        Assert.Equal(ApplicationLineageDisposition.ForkLatched, fork.Disposition);
        Assert.True(fork.Next.ForkLatched);
        Assert.Equal(ApplicationCoreRejection.InvalidLineage,
            Assert.Throws<ApplicationCoreFormatException>(() =>
                ApplicationCoreVerifier.PrepareDab1Transition(fork.Next, successor)).Rejection);
    }

    [Fact]
    public void Dab1Lineage_RejectsCrossDidSuccessorAndSameGenerationFork()
    {
        var owner = VerifiedFixture.Create();
        var genesis = owner.AuthorAndVerifyDab1(0, new byte[32]);
        var ownerSuccessor = owner.AuthorAndVerifyDab1(1, genesis.Record.RecordHash.Span);
        var otherDid = VerifiedFixture.Create(accountValue: 0x91, deviceValue: 0x92);
        var crossDidSuccessor = otherDid.AuthorAndVerifyDab1(1, genesis.Record.RecordHash.Span);

        var started = ApplicationCoreVerifier.StartDab1Lineage(genesis);
        AssertLineageFailure(() =>
            ApplicationCoreVerifier.PrepareDab1Transition(started.Next, crossDidSuccessor));

        var accepted = ApplicationCoreVerifier.PrepareDab1Transition(started.Next, ownerSuccessor);
        var crossDidSameGeneration = otherDid.AuthorAndVerifyDab1(
            ownerSuccessor.Record.BindingGeneration,
            ownerSuccessor.Record.PredecessorDab1Hash.Span);
        AssertLineageFailure(() =>
            ApplicationCoreVerifier.PrepareDab1Transition(accepted.Next, crossDidSameGeneration));
    }

    [Fact]
    public void Dab1Lineage_MaxGenerationRejectsCanonicallyWithoutOverflow()
    {
        var fixture = VerifiedFixture.Create();
        var maxHead = fixture.AuthorAndVerifyDab1(ulong.MaxValue, ApplicationCoreFixture.Bytes(32, 0x71));
        var wrappedCandidate = fixture.AuthorAndVerifyDab1(0, new byte[32]);
        var state = new Dab1LineageState(maxHead, forkLatched: false);

        AssertLineageFailure(() =>
            ApplicationCoreVerifier.PrepareDab1Transition(state, wrappedCandidate));
    }

    [Fact]
    public void Dmd1Lineage_EnforcesSuccessorReplayAndPermanentForkLatch()
    {
        var fixture = VerifiedFixture.Create();
        var genesis = fixture.AuthorAndVerifyDmd1(1, new byte[32]);
        var started = ApplicationCoreVerifier.StartDmd1Lineage(genesis);
        var successor = fixture.AuthorAndVerifyDmd1(2, genesis.Record.RecordHash.Span);
        var accepted = ApplicationCoreVerifier.PrepareDmd1Transition(started.Next, successor);

        Assert.Equal(ApplicationLineageDisposition.AcceptedSuccessor, accepted.Disposition);
        Assert.Equal(ApplicationLineageDisposition.ExactReplay,
            ApplicationCoreVerifier.PrepareDmd1Transition(accepted.Next, successor).Disposition);

        var conflicting = fixture.AuthorAndVerifyDmd1(
            2, genesis.Record.RecordHash.Span, issuedAt: 101);
        var fork = ApplicationCoreVerifier.PrepareDmd1Transition(accepted.Next, conflicting);
        Assert.Equal(ApplicationLineageDisposition.ForkLatched, fork.Disposition);
        Assert.True(fork.Next.ForkLatched);
        Assert.Equal(ApplicationCoreRejection.InvalidLineage,
            Assert.Throws<ApplicationCoreFormatException>(() =>
                ApplicationCoreVerifier.PrepareDmd1Transition(fork.Next, successor)).Rejection);
    }

    [Fact]
    public void VerifiedDmc2_RequiresExactAuthenticatedOuterAndRatchetContext()
    {
        var parsed = ApplicationCoreFixture.Message(
            ApplicationCoreCodec.CreateMessageCreatePayload("authenticated"));
        using var exact = ApplicationCoreFixture.VerifiedEnvelope(parsed);
        var verified = ApplicationCoreVerifier.VerifyDmc2(exact);

        Assert.Equal("authenticated", Assert.IsType<MessageCreateDmc2Payload>(verified.Payload).Text);
        var substitutions = new[]
        {
            ApplicationCoreFixture.VerifiedEnvelope(parsed,
                authenticatedNetwork: ApplicationCoreFixture.Bytes(16, 0xa1),
                envelopeNetwork: ApplicationCoreFixture.Bytes(16, 0xa1)),
            ApplicationCoreFixture.VerifiedEnvelope(parsed,
                authenticatedAccount: ApplicationCoreFixture.Bytes(32, 0xa2)),
            ApplicationCoreFixture.VerifiedEnvelope(parsed,
                authenticatedDevice: ApplicationCoreFixture.Bytes(32, 0xa3),
                envelopeDevice: ApplicationCoreFixture.Bytes(32, 0xa3)),
            ApplicationCoreFixture.VerifiedEnvelope(parsed,
                authenticatedConversation: ApplicationCoreFixture.Bytes(32, 0xa4)),
        };
        foreach (var substitution in substitutions)
        {
            using (substitution)
                AssertVerificationFailure(() => ApplicationCoreVerifier.VerifyDmc2(substitution));
        }
    }

    [Fact]
    public void Dca1_CurrentAuthorityRequiresTrustedTimeInsideHalfOpenWindow()
    {
        var fixture = VerifiedFixture.Create();
        var binding = fixture.AuthorAndVerifyDab1(0, new byte[32]);
        var directory = fixture.AuthorAndVerifyDmd1(1, new byte[32]);
        var verified = fixture.AuthorAndVerifyDca1(binding, directory);

        Assert.Equal(10UL,
            ApplicationCoreVerifier.RequireDca1CurrentlyAuthoritative(verified, 10).TrustedUnixSeconds);
        Assert.Equal(19UL,
            ApplicationCoreVerifier.RequireDca1CurrentlyAuthoritative(verified, 19).TrustedUnixSeconds);
        AssertVerificationFailure(() =>
            ApplicationCoreVerifier.RequireDca1CurrentlyAuthoritative(verified, 9));
        AssertVerificationFailure(() =>
            ApplicationCoreVerifier.RequireDca1CurrentlyAuthoritative(verified, 20));
    }

    private static void AssertLineageFailure(Action action)
    {
        var exception = Assert.Throws<ApplicationCoreFormatException>(action);
        Assert.Equal(ApplicationCoreValidationStage.CryptographicVerification, exception.Stage);
        Assert.Equal(ApplicationCoreRejection.InvalidLineage, exception.Rejection);
    }

    private static void AssertVerificationFailure(Action action)
    {
        var exception = Assert.Throws<ApplicationCoreFormatException>(action);
        Assert.Equal(ApplicationCoreValidationStage.CryptographicVerification, exception.Stage);
        Assert.Equal(ApplicationCoreRejection.VerificationFailed, exception.Rejection);
    }

    private sealed class VerifiedFixture
    {
        private VerifiedFixture(
            byte[] network,
            byte[] accountId,
            byte[] deviceId,
            KeyPair addressKey,
            KeyPair accountKey,
            KeyPair deviceIssuerKey,
            KeyPair deviceKey,
            VerifiedAccount account,
            VerifiedRevocationState revocations,
            VerifiedApplicationIdentityClosure identity,
            ParsedDid1 deepId)
        {
            Network = network;
            AccountId = accountId;
            DeviceId = deviceId;
            AddressKey = addressKey;
            AccountKey = accountKey;
            DeviceIssuerKey = deviceIssuerKey;
            DeviceKey = deviceKey;
            Account = account;
            Revocations = revocations;
            Identity = identity;
            DeepId = deepId;
        }

        internal const ushort DeploymentProfileId = 7;
        internal byte[] Network { get; }
        internal byte[] AccountId { get; }
        internal byte[] DeviceId { get; }
        internal KeyPair AddressKey { get; }
        internal KeyPair AccountKey { get; }
        internal KeyPair DeviceIssuerKey { get; }
        internal KeyPair DeviceKey { get; }
        internal VerifiedAccount Account { get; }
        internal VerifiedRevocationState Revocations { get; }
        internal VerifiedApplicationIdentityClosure Identity { get; }
        internal ParsedDid1 DeepId { get; }

        internal static VerifiedFixture Create(
            KeyPair? existingAddressKey = null,
            byte accountValue = 0x22,
            byte deviceValue = 0x33)
        {
            var network = ApplicationCoreFixture.Bytes(16, 0x11);
            var accountId = ApplicationCoreFixture.Bytes(32, accountValue);
            var deviceId = ApplicationCoreFixture.Bytes(32, deviceValue);
            var addressKey = existingAddressKey ?? PublicKeyAuth.GenerateKeyPair();
            var accountKey = PublicKeyAuth.GenerateKeyPair();
            var deviceIssuerKey = PublicKeyAuth.GenerateKeyPair();
            var revocationKey = PublicKeyAuth.GenerateKeyPair();
            var resetKey = PublicKeyAuth.GenerateKeyPair();

            var dpaFields = MinimumFields(RecordDefinitions.Dpa1);
            dpaFields[0] = network;
            dpaFields[1] = U64(1);
            dpaFields[2] = U64(1);
            dpaFields[4] = accountKey.PublicKey;
            dpaFields[5] = deviceIssuerKey.PublicKey;
            dpaFields[6] = revocationKey.PublicKey;
            dpaFields[7] = resetKey.PublicKey;
            dpaFields[8] = ApplicationCoreFixture.Bytes(32, 0x44);
            dpaFields[9] = U64(100);
            dpaFields[10] = U64(1);
            dpaFields[11] = U16(ArtifactRegistry.IdentityAuthV1Ed25519);
            var certificate = IdentityCodec.DecodeAccountCertificate(
                CanonicalGrammar.Encode(RecordDefinitions.Dpa1, dpaFields));
            var account = new VerifiedAccount(certificate, accountId);
            var drs = ApplicationCoreFixture.Revocations(network, accountId);
            var revocations = new VerifiedRevocationState(account, drs, new RevocationCatalog([]));

            var deviceEd = PublicKeyAuth.GenerateKeyPair();
            var dpdFields = MinimumFields(RecordDefinitions.Dpd1);
            dpdFields[0] = network;
            dpdFields[1] = accountId;
            dpdFields[2] = U64(1);
            dpdFields[3] = deviceId;
            dpdFields[4] = U64(1);
            dpdFields[5] = deviceEd.PublicKey;
            dpdFields[6] = ApplicationCoreFixture.Bytes(32, 0x51);
            dpdFields[7] = ApplicationCoreFixture.Bytes(32, 0x52);
            dpdFields[8] = U64(1);
            dpdFields[10] = ApplicationCoreFixture.Bytes(32, 0x53);
            dpdFields[11] = U64(1);
            dpdFields[13] = U64(0);
            dpdFields[14] = ApplicationCoreFixture.Bytes(32, 0x54);
            dpdFields[15] = U64(100);
            dpdFields[16] = U64(1_000);
            dpdFields[17] = U64((ulong)DeviceCapabilities.MailboxRoleIssuer);
            dpdFields[18] = U16(ArtifactRegistry.IdentityAuthV1Ed25519);
            dpdFields[20] = ApplicationCoreFixture.Bytes(32, 0x55);
            var certificateDevice = IdentityCodec.DecodeDeviceCertificate(
                CanonicalGrammar.Encode(RecordDefinitions.Dpd1, dpdFields));
            var device = new VerifiedDevice(certificateDevice, revocations,
                new X25519Possession(X25519PossessionRole.Device, dpdFields[20].Span));
            var identity = ApplicationCoreVerifier.CreateIdentityClosure(account, revocations, [device]);
            var deepId = ApplicationCoreCodec.AuthorDid1(addressKey.PublicKey,
                ApplicationCoreFixture.Bytes(16, 0x66));
            return new VerifiedFixture(network, accountId, deviceId, addressKey, accountKey,
                deviceIssuerKey, deviceEd, account, revocations, identity, deepId);
        }

        internal VerifiedDab1 AuthorAndVerifyDab1(
            ulong generation,
            ReadOnlySpan<byte> predecessor)
        {
            var realm = ApplicationCoreCodec.DeriveIdentityRealmId(Network, DeploymentProfileId);
            var dpa = Ref(Account.Certificate);
            var unsigned = ApplicationCoreCodec.AuthorDab1(DeepId.RecordHash.Span, realm.Span,
                generation, predecessor, AccountId, 1, dpa, new byte[64], new byte[64]);
            var addressSignature = PublicKeyAuth.SignDetached(
                unsigned.AddressSignatureInput.ToArray(), AddressKey.PrivateKey);
            var accountSignature = PublicKeyAuth.SignDetached(
                unsigned.AccountSignatureInput.ToArray(), AccountKey.PrivateKey);
            var parsed = ApplicationCoreCodec.AuthorDab1(DeepId.RecordHash.Span, realm.Span,
                generation, predecessor, AccountId, 1, dpa, addressSignature, accountSignature);
            return ApplicationCoreVerifier.VerifyDab1(parsed, DeepId, Identity, DeploymentProfileId);
        }

        internal VerifiedDmd1 AuthorAndVerifyDmd1(
            ulong generation,
            ReadOnlySpan<byte> predecessor,
            ulong issuedAt = 100)
        {
            var entry = new DeviceDirectoryEntry(DeviceId, Ref(Identity.ActiveDevices[0].Certificate));
            var unsigned = ApplicationCoreCodec.AuthorDmd1(Network, AccountId, 1,
                Ref(Account.Certificate), Ref(Revocations.Snapshot), generation, predecessor,
                [entry], issuedAt, new byte[64]);
            var signature = PublicKeyAuth.SignDetached(
                unsigned.SignatureInput.ToArray(), DeviceIssuerKey.PrivateKey);
            var parsed = ApplicationCoreCodec.AuthorDmd1(Network, AccountId, 1,
                Ref(Account.Certificate), Ref(Revocations.Snapshot), generation, predecessor,
                [entry], issuedAt, signature);
            return ApplicationCoreVerifier.VerifyDmd1(parsed, Identity);
        }

        internal VerifiedDca1 AuthorAndVerifyDca1(VerifiedDab1 binding, VerifiedDmd1 directory) =>
            ApplicationCoreVerifier.VerifyDca1(
                AuthorDca1(binding, directory, DeviceId), binding, directory);

        internal ParsedDca1 AuthorDca1(
            VerifiedDab1 binding,
            VerifiedDmd1 directory,
            ReadOnlySpan<byte> publisher)
        {
            var dabReference = ApplicationCoreCodec.CreateArtifactReference(
                ApplicationCoreCodec.Dab1ArtifactTypeCode,
                checked((uint)binding.Record.CanonicalBytes.Length),
                binding.Record.RecordHash.Span);
            var unsigned = ApplicationCoreCodec.AuthorDca1(Network, AccountId, Ref(Account.Certificate),
                directory.Record.DirectoryGeneration, directory.Record.RecordHash.Span,
                ApplicationCoreFixture.Bytes(32, 0x77), publisher, 3, 100, 10, 20,
                new byte[64], DeepId.RecordHash.Span, dabReference);
            var signature = PublicKeyAuth.SignDetached(
                unsigned.SignatureInput.ToArray(), AccountKey.PrivateKey);
            return ApplicationCoreCodec.AuthorDca1(Network, AccountId, Ref(Account.Certificate),
                directory.Record.DirectoryGeneration, directory.Record.RecordHash.Span,
                ApplicationCoreFixture.Bytes(32, 0x77), publisher, 3, 100, 10, 20,
                signature, DeepId.RecordHash.Span, dabReference);
        }

        private static ApplicationArtifactReference Ref(CanonicalIdentityArtifact artifact) =>
            ApplicationCoreCodec.CreateArtifactReference((ushort)artifact.ArtifactType,
                checked((uint)artifact.CanonicalBytes.Length), artifact.CanonicalHash.Span);

        private static ReadOnlyMemory<byte>[] MinimumFields(RecordDefinition definition) =>
            definition.Fields.Select(field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();

        private static byte[] U64(ulong value)
        {
            var bytes = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
            return bytes;
        }

        private static byte[] U16(ushort value)
        {
            var bytes = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
            return bytes;
        }
    }
}
