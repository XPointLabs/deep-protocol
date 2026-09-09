using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.Tests.ApplicationCore;
using Deep.Protocol.DeepNative;
using Sodium;

namespace Deep.Protocol.Tests.ContactV1;

public sealed class ContactCodecTests
{
    [Fact]
    public void FrozenMachinePrimitivesExecuteAgainstExactFixtureBytes()
    {
        var manifest = File.ReadAllBytes(FindSpec("contact-codec-v1.vectors.json"));
        Assert.Equal("c07ef886edc5ea829dada8ad9880e37514844c29e82c0d0e3611691957c831c1", Convert.ToHexString(SHA256.HashData(manifest)).ToLowerInvariant());
        using var anchor = JsonDocument.Parse(File.ReadAllBytes(FindSpec("contact-codec-v1.vectors.anchor.json")));
        Assert.Equal("c07ef886edc5ea829dada8ad9880e37514844c29e82c0d0e3611691957c831c1", anchor.RootElement.GetProperty("sha256").GetString());
        using var document = JsonDocument.Parse(manifest);
        Assert.Equal("FROZEN_TARGET_NOT_ACTIVE", document.RootElement.GetProperty("status").GetString());
        Assert.False(ContactCodec.RuntimeActivation);
        foreach (var vector in document.RootElement.GetProperty("primitives").EnumerateArray())
        {
            var bytes = Convert.FromHexString(vector.GetProperty("fixtureBytesHex").GetString()!);
            Assert.Equal(vector.GetProperty("sha256").GetString(), Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant());
            var id = vector.GetProperty("id").GetString();
            var expected = id switch
            {
                "xir1-signature-projection" => Records.Xir.SigningProjection,
                "xur1-signature-projection" => Records.Xur.SigningProjection,
                "xra1-core-projection" => Records.Xra.SigningProjection,
                "pmt2-core-projection" => Records.Pmt.SigningProjection,
                "pms2-selection-projection" => ContactCodec.Project(Records.Pms, [1,2,3,4,5,6]),
                "xrc1-core-projection" => Records.Xrc.SigningProjection,
                "xss1-core-projection" => Records.Xss.SigningProjection,
                "xrr1-core-projection" => Records.Xrr.SigningProjection,
                "dcb1-signature-projection" => Records.Dcb.SigningProjection,
                "dcr1-closure-grammar" => Records.Dcr.CanonicalBytes,
                "dia1-canonical-grammar" => Records.Dia.CanonicalBytes,
                "dmc2-contact-hello" => ContactFixtures.Hello.CanonicalBytes,
                "dmc2-contact-accept" => ContactFixtures.Accept.CanonicalBytes,
                "dmc2-contact-reject" => ContactFixtures.Reject.CanonicalBytes,
                "dmc2-contact-route-update" => ContactFixtures.Route.CanonicalBytes,
                _ => default,
            };
            if (!expected.IsEmpty) Assert.Equal(expected.ToArray(), bytes);
        }

        var primitives = document.RootElement.GetProperty("primitives").EnumerateArray().ToArray();
        foreach (var fixture in document.RootElement.GetProperty("ed25519Fixtures").EnumerateArray())
        {
            var projectionId = fixture.GetProperty("projectionPrimitiveId").GetString();
            var projection = primitives.Single(item => item.GetProperty("id").GetString() == projectionId);
            var projectionBytes = Convert.FromHexString(projection.GetProperty("fixtureBytesHex").GetString()!);
            var message = Convert.FromHexString(fixture.GetProperty("signatureInputHex").GetString()!);
            var independentlyComposed = ComposeSignatureInput(
                fixture.GetProperty("signatureDomain").GetString()!, projectionBytes);
            var seed = Convert.FromHexString(fixture.GetProperty("seedHex").GetString()!);
            var publicKey = Convert.FromHexString(fixture.GetProperty("publicKeyHex").GetString()!);
            var signature = Convert.FromHexString(fixture.GetProperty("signatureHex").GetString()!);
            var keyPair = PublicKeyAuth.GenerateKeyPair(seed);

            Assert.Equal(independentlyComposed, message);
            Assert.Equal(publicKey, keyPair.PublicKey);
            Assert.True(PublicKeyAuth.VerifyDetached(signature, message, publicKey));
        }

        foreach (var vector in document.RootElement.GetProperty("records").EnumerateArray())
        {
            var bytes = Convert.FromHexString(vector.GetProperty("fixtureBytesHex").GetString()!);
            Assert.Equal(vector.GetProperty("sha256").GetString(), Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant());
            var target = vector.GetProperty("target").GetString()!;
            if (target.StartsWith("DMC2/", StringComparison.Ordinal))
            {
                var decoded = ApplicationCoreCodec.DecodeDmc2(bytes);
                Assert.Equal(vector.GetProperty("contentKind").GetInt32(), (int)decoded.ContentKind);
                Assert.Equal(bytes, decoded.CanonicalBytes.ToArray());
                continue;
            }

            var decodedContact = ContactCodec.Decode(bytes);
            Assert.Equal(target, decodedContact.Magic);
            Assert.Equal(vector.GetProperty("artifactHash").GetString(), Convert.ToHexString(decodedContact.ArtifactHash.Span).ToLowerInvariant());
            Assert.Equal(vector.GetProperty("coreHash").GetString(), Convert.ToHexString(decodedContact.CoreHash.Span).ToLowerInvariant());
            Assert.Equal(bytes, decodedContact.CanonicalBytes.ToArray());
        }

        foreach (var hostile in document.RootElement.GetProperty("hostileFixtures").EnumerateArray())
        {
            var bytes = Convert.FromHexString(hostile.GetProperty("fixtureBytesHex").GetString()!);
            Assert.Equal(hostile.GetProperty("sha256").GetString(), Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant());
            if (hostile.GetProperty("api").GetString() == "Contact")
            {
                var error = Assert.Throws<ContactFormatException>(() => ContactCodec.Decode(bytes));
                Assert.Equal(hostile.GetProperty("stage").GetString(), error.Stage.ToString());
                Assert.Equal(hostile.GetProperty("rejection").GetString(), error.Code);
            }
            else
            {
                var error = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.DecodeDmc2(bytes));
                Assert.Equal(hostile.GetProperty("rejection").GetString(), error.Rejection.ToString());
            }
        }
    }

    private static byte[] ComposeSignatureInput(string domain, ReadOnlySpan<byte> projection)
    {
        var label = System.Text.Encoding.ASCII.GetBytes(domain);
        var output = new byte[label.Length + 1 + 2 + 4 + projection.Length];
        label.CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(label.Length + 1), 0x0201);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(label.Length + 3), checked((uint)projection.Length));
        projection.CopyTo(output.AsSpan(label.Length + 7));
        return output;
    }

    [Fact]
    public void IndependentFrozenRecordsRoundTripWithExactProjectionAndDefensiveOwnership()
    {
        foreach (var record in Records.All())
        {
            var decoded = ContactCodec.Decode(record.CanonicalBytes.Span);
            Assert.Equal(record.Magic, decoded.Magic);
            Assert.Equal(record.CanonicalBytes.ToArray(), decoded.CanonicalBytes.ToArray());
            Assert.Equal(32, decoded.ArtifactHash.Length);
            var copy = decoded.CanonicalBytes.ToArray(); copy[0] ^= 1;
            Assert.Equal(record.CanonicalBytes.ToArray(), decoded.CanonicalBytes.ToArray());
        }
        Assert.Equal(539, Records.Xir.SigningProjection.Length);
        Assert.Equal(466, Records.Xur.SigningProjection.Length);
        Assert.Equal(550, Records.Xra.CanonicalBytes.Length);
        Assert.Equal(478, Records.Xra.SigningProjection.Length);
        Assert.Equal(32, Records.Pmt.CoreHash.Length);
        Assert.Equal(32, Records.Xrr.CoreHash.Length);
    }

    [Fact]
    public void ContactHelloAcceptAndRejectAreTypedAndExact()
    {
        var hello = ContactCodecValidation.CreateContactHelloPayload(B(32, 1), Ref("DAB1", 2), B(32, 3), B(32, 4),
            ContactPolicy.ManualApproval | ContactPolicy.AllowRouteUpdates, Records.Xur.CanonicalBytes.Span);
        var accept = ContactCodecValidation.CreateContactAcceptPayload(B(32, 5), B(32, 6), Ref("DAB1", 7), B(32, 8),
            ContactPolicy.None, Records.Xur.CanonicalBytes.Span);
        var reject = ContactCodecValidation.CreateContactRejectPayload(B(32, 9), B(32, 10), ContactRejectReason.Policy);
        Assert.Equal(678, hello.CanonicalBytes.Length); Assert.Equal(678, accept.CanonicalBytes.Length); Assert.Equal(66, reject.CanonicalBytes.Length);
        foreach (var payload in new Dmc2Payload[] { hello, accept, reject })
        {
            var dmc = ContactCodecValidation.AuthorDmc2(B(16, 11), B(32, 12), B(32, 13), B(32, 14), B(32, 15), 1, 1_000, 2_000,
                Dmc2Flags.None, [], payload);
            Assert.Equal(payload.Kind, ApplicationCoreCodec.DecodeDmc2(dmc.CanonicalBytes.Span).ContentKind);
        }
    }

    [Fact]
    public void HostileHeaderTagsZeroAndMalformedRouteKindRejectBeforeAnyActivation()
    {
        var canonical = Records.Xur.CanonicalBytes.ToArray(); canonical[10] = 1;
        Assert.Equal(ContactValidationStage.Header, Assert.Throws<ContactFormatException>(() => ContactCodec.Decode(canonical)).Stage);

        canonical = Records.Xur.CanonicalBytes.ToArray(); BinaryPrimitives.WriteUInt16BigEndian(canonical.AsSpan(12), 2);
        Assert.Equal(ContactValidationStage.FieldScan, Assert.Throws<ContactFormatException>(() => ContactCodec.Decode(canonical)).Stage);

        canonical = Records.Xur.CanonicalBytes.ToArray(); Array.Clear(canonical, FieldOffset(canonical, 2), 32);
        Assert.Equal(ContactValidationStage.Scalar, Assert.Throws<ContactFormatException>(() => ContactCodec.Decode(canonical)).Stage);

        var dmc = ApplicationCoreCodec.AuthorDmc2(B(16, 1), B(32, 2), B(32, 3), B(32, 4), B(32, 5), 1, 1_000, 2_000,
            Dmc2Flags.None, [], ApplicationCoreCodec.CreateMessageCreatePayload("x")).CanonicalBytes.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(dmc.AsSpan(FieldOffset(dmc, 9), 2), 14);
        var error = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.DecodeDmc2(dmc));
        Assert.Equal(ApplicationCoreRejection.InvalidFieldLength, error.Rejection);
    }

    [Fact]
    public void ContactRouteUpdate_IsTypedHashClosedAndDefensivelyOwned()
    {
        var closure = Records.RouteClosure;
        var payload = ContactCodecValidation.CreateContactRouteUpdatePayload(B(32, 90), 0, new byte[32],
            closure.Xrr, closure.Xra, closure.Xrc, closure.Xss, closure.Pmt, closure.Pms);
        Assert.Equal(4_215, payload.CanonicalBytes.Length);
        var dmc = ContactCodecValidation.AuthorDmc2(B(16, 1), B(32, 91), B(32, 92), B(32, 93), B(32, 94), 1,
            1_000, 2_000, Dmc2Flags.None, [], payload);
        var decoded = Assert.IsType<ContactRouteUpdateDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(dmc.CanonicalBytes.Span).ParsedPayload);
        Assert.Equal(Dmc2ContentKind.ContactRouteUpdate, decoded.Kind);
        Assert.Equal(closure.Xrr.CanonicalBytes.ToArray(), decoded.Reachability.CanonicalBytes.ToArray());
        var copy = decoded.RelationshipId.ToArray(); copy[0] ^= 1;
        Assert.Equal(B(32, 90), decoded.RelationshipId.ToArray());

        var hostile = dmc.CanonicalBytes.ToArray();
        var payloadOffset = FieldOffset(hostile, 12);
        var xrrOffset = payloadOffset + 77;
        hostile[FieldOffset(hostile.AsSpan(xrrOffset), 9) + xrrOffset] ^= 1;
        var error = Assert.Throws<ApplicationCoreFormatException>(() => ApplicationCoreCodec.DecodeDmc2(hostile));
        Assert.Equal(ApplicationCoreRejection.CrossFieldMismatch, error.Rejection);
    }

    [Fact]
    public void ContactRouteUpdate_MaximumClosureUsesTheExactTableBound()
    {
        var closure = Records.MaximumRouteClosure;
        var payload = ContactCodecValidation.CreateContactRouteUpdatePayload(B(32, 95), 0, new byte[32],
            closure.Xrr, closure.Xra, closure.Xrc, closure.Xss, closure.Pmt, closure.Pms);
        Assert.Equal(23_367, payload.CanonicalBytes.Length);
    }

    [Fact]
    public void SignatureAndContactOwnedClosureAreBothFailClosed()
    {
        var signature = Assert.Throws<ContactFormatException>(() => ContactCodec.VerifyDeviceSignature(Records.Xur, B(32, 1)));
        Assert.Equal(ContactValidationStage.Signature, signature.Stage);

        var xur = ContactCodecValidation.AuthorRecord("XUR1", [B(16,1),B(32,2),B(32,3),U64(0),new byte[32],
            ContactCodec.ArtifactReference("PMT2", Records.Pmt).CanonicalBytes,B(32,4),B(32,5),B(32,6),U16(7),U64(1),U64(2),B(32,7),Ref("DPD1",8),B(64,9)]);
        ContactCodec.VerifyContactOwnedClosure(xur, new Resolver(Records.Pmt));
        var closure = Records.RouteClosure;
        var resolver = new Resolver(closure.Pmt, closure.Xra, closure.Xrc, closure.Xss);
        ContactCodec.VerifyContactOwnedClosure(closure.Xra, resolver);
        ContactCodec.VerifyContactOwnedClosure(closure.Xrc, resolver);
        ContactCodec.VerifyContactOwnedClosure(closure.Xss, resolver);
        ContactCodec.VerifyContactOwnedClosure(closure.Xrr, resolver);
        var missing = Assert.Throws<ContactFormatException>(() => ContactCodec.VerifyContactOwnedClosure(Records.Xrc, new Resolver(Records.Pmt)));
        Assert.Equal(ContactValidationStage.Closure, missing.Stage);
    }

    [Fact]
    public void ExactXpsAndDpdDirectoryCorrespondenceRejectMutatedCanonicalBytes()
    {
        var invalidXps = Records.Dcb.CanonicalBytes.ToArray();
        invalidXps[FieldOffset(invalidXps, 12) + 5] ^= 1;
        var xpsError = Assert.Throws<ContactFormatException>(() => ContactCodec.Decode(invalidXps));
        Assert.Equal(ContactValidationStage.Derived, xpsError.Stage);
        Assert.Equal("InvalidXps1CanonicalRecord", xpsError.Code);

        var invalidDpd = Records.Dcr.CanonicalBytes.ToArray();
        var dpdOffset = FieldOffset(invalidDpd, 4) + 6 + 356 + 6;
        invalidDpd[dpdOffset + 40] ^= 1;
        var dpdError = Assert.Throws<ContactFormatException>(() => ContactCodec.Decode(invalidDpd));
        Assert.Equal(ContactValidationStage.Derived, dpdError.Stage);
        Assert.Equal("EmbeddedDpd1Rejected", dpdError.Code);
    }

    [Fact]
    public void U32OverflowAndProductionAuthoringGateAreControlled()
    {
        var overflow = Records.Xra.CanonicalBytes.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(overflow.AsSpan(16, 4), uint.MaxValue);
        var contactError = Assert.Throws<ContactFormatException>(() => ContactCodec.Decode(overflow));
        Assert.Equal(ContactValidationStage.Bounds, contactError.Stage);
        Assert.Equal("TruncatedField", contactError.Code);

        Assert.False(ContactCodec.RuntimeActivation);
        Assert.False(typeof(ContactCodecValidation).IsPublic);
        Assert.Throws<InvalidOperationException>(() => ContactCodec.Author("XUR1", [B(16,1),B(32,2),B(32,3),U64(0),new byte[32],Ref("PMT2",4),B(32,5),B(32,6),B(32,7),U16(1),U64(1),U64(2),B(32,8),Ref("DPD1",9),B(64,10)]));
        Assert.Throws<InvalidOperationException>(() => ApplicationCoreCodec.CreateContactRejectPayload(B(32, 1), B(32, 2), ContactRejectReason.Policy));
        Assert.NotEmpty(ContactCodecValidation.CreateContactRejectPayload(B(32, 1), B(32, 2), ContactRejectReason.Policy).CanonicalBytes.ToArray());
    }

    [Fact]
    public void StrictClosureBoundsAndRouteBindingsRejectBeforeContactActivation()
    {
        var fields = Enumerable.Range(1, 24).Select(Records.Dcb.Field).ToArray();
        fields[14] = new byte[] { 0xc0, 0x80 }; // overlong UTF-8 for U+0000
        var utf8 = Assert.Throws<ContactFormatException>(() => ContactCodecValidation.AuthorRecord("DCB1", fields));
        Assert.Equal("NonCanonicalUtf8", utf8.Code);

        var closure = Records.RouteClosure;
        var xrr = closure.Xrr.CanonicalBytes.ToArray();
        Array.Clear(xrr, FieldOffset(xrr, 14), 2);
        var minReader = Assert.Throws<ContactFormatException>(() => ContactCodec.Decode(xrr));
        Assert.Equal("InvalidReachabilityPolicy", minReader.Code);

        var xrc = closure.Xrc.CanonicalBytes.ToArray();
        xrc[FieldOffset(xrc, 8) + 6] ^= 1;
        var changedXrc = ContactCodec.Decode("XRC1", xrc);
        var binding = Assert.Throws<ContactFormatException>(() => ContactCodec.ValidateRouteUpdateGraph(
            closure.Xrr, closure.Xra, changedXrc, closure.Xss, closure.Pmt, closure.Pms));
        Assert.Equal(ContactValidationStage.Closure, binding.Stage);

        var support = Assert.Throws<ContactFormatException>(() => ContactCodecValidation.AuthorRecord("DCR1", [
            Records.Dcr.Field(1), Records.Dcr.Field(2), U16(2), new byte[16_385]]));
        Assert.Equal("InvalidResolverClosureLength", support.Code);
    }

    [Fact]
    public void DcrPromotionRequiresApplicationVerifiedCapabilities()
    {
        var method = typeof(ContactCodec).GetMethod(nameof(ContactCodec.VerifyDcr1Closure));
        Assert.NotNull(method);
        Assert.Equal(typeof(VerifiedContactBundleClosure), method!.ReturnType);
        Assert.Equal(new[] { typeof(ContactRecord), typeof(CurrentlyAuthoritativeDca1),
            typeof(VerifiedAccountDirectoryFreshness), typeof(ReadOnlySpan<byte>), typeof(ulong) },
            method.GetParameters().Select(parameter => parameter.ParameterType));
        Assert.False(typeof(VerifiedContactBundleClosure).GetConstructors().Any());
        Assert.False(typeof(VerifiedAccountDirectoryFreshness).GetConstructors().Any());
        Assert.False(typeof(VerifiedContactNetworkAuthority).GetConstructors().Any());
        Assert.False(typeof(VerifiedContactRouteClosure).GetConstructors().Any());
    }

    private static int FieldOffset(ReadOnlySpan<byte> bytes, int sought)
    {
        var offset = 12; var count = BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(8, 2));
        for (var i = 0; i < count; i++) { var tag = BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(offset, 2)); var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(offset + 4, 4))); offset += 8; if (tag == sought) return offset; offset += length; }
        throw new InvalidOperationException();
    }
    private static byte[] B(int length, byte seed) => Enumerable.Range(0, length).Select(i => unchecked((byte)(seed + i))).ToArray();
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
    private static byte[] U32(uint value) { var bytes = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(bytes, value); return bytes; }
    private static byte[] U16(ushort value) { var bytes = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); return bytes; }
    private static byte[] Ref(string magic, byte seed) { var bytes = new byte[38]; System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1); B(32, seed).CopyTo(bytes, 6); return bytes; }
    private static byte[] Ref(string magic, ReadOnlySpan<byte> hash) { var bytes = new byte[38]; System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1); hash.CopyTo(bytes.AsSpan(6)); return bytes; }
    private static string FindSpec(string name) { var path = Directory.GetCurrentDirectory(); while (path is not null) { var candidate = Path.Combine(path, "..", "docs", "survival-program", "releases", "v3.0.0", "specs", name); if (File.Exists(candidate)) return candidate; path = Directory.GetParent(path)?.FullName; } throw new FileNotFoundException(name); }

    private static class ContactFixtures
    {
        internal static readonly ContactRouteUpdateDmc2Payload Route = CreateRoute();
        internal static readonly ContactHelloDmc2Payload Hello = ContactCodecValidation.CreateContactHelloPayload(B(32, 1), Ref("DAB1", 2), B(32, 3), B(32, 4), ContactPolicy.AllowRouteUpdates, Records.Xur.CanonicalBytes.Span);
        internal static readonly ContactAcceptDmc2Payload Accept = ContactCodecValidation.CreateContactAcceptPayload(B(32, 5), B(32, 6), Ref("DAB1", 7), B(32, 8), ContactPolicy.None, Records.Xur.CanonicalBytes.Span);
        internal static readonly ContactRejectDmc2Payload Reject = ContactCodecValidation.CreateContactRejectPayload(B(32, 9), B(32, 10), ContactRejectReason.Policy);
        internal static readonly ParsedDmc2 HelloDmc = Author(Hello, 11);
        internal static readonly ParsedDmc2 AcceptDmc = Author(Accept, 12);
        internal static readonly ParsedDmc2 RejectDmc = Author(Reject, 13);
        internal static readonly ParsedDmc2 RouteDmc = Author(Route, 14);

        private static ContactRouteUpdateDmc2Payload CreateRoute()
        {
            var closure = Records.RouteClosure;
            return ContactCodecValidation.CreateContactRouteUpdatePayload(B(32, 90), 0, new byte[32], closure.Xrr, closure.Xra, closure.Xrc, closure.Xss, closure.Pmt, closure.Pms);
        }

        private static ParsedDmc2 Author(Dmc2Payload payload, byte seed) => ContactCodecValidation.AuthorDmc2(B(16, 1), B(32, (byte)(seed + 1)), B(32, (byte)(seed + 2)), B(32, (byte)(seed + 3)), B(32, (byte)(seed + 4)), 1, 1_000, 2_000, Dmc2Flags.None, [], payload);
    }

    internal static class Records
    {
        internal static readonly ContactRecord Pmt = ContactCodecValidation.AuthorRecord("PMT2", [B(16,1),U64(0),new byte[32],Ref("PMA2",2),Ref("XNV1",3),U64(1),new byte[] { 2 },U16(2),Rows(136,2,4),U64(1),U64(1),U64(2),new byte[32],Ref("ADH1",5),new byte[] { 2 },Rows(96,2,6)]);
        internal static readonly ContactRecord Xra = ContactCodecValidation.AuthorRecord("XRA1", [B(16,7),B(32,8),U64(0),new byte[32],ContactCodec.ArtifactReference("PMT2", Pmt).CanonicalBytes,B(32,10),U16(1),U32(1),B(32,11),B(32,12),B(32,13),U64(1),U64(2),B(32,14),Ref("DPD1",15),B(64,16)]);
        internal static readonly ContactRecord Xir = ContactCodecValidation.AuthorRecord("XIR1", [B(16,7),B(32,8),U64(0),new byte[32],Ref("PMT2",9),B(32,10),B(32,11),B(32,12),new byte[] { 1 },U32(0),U16(1),B(32,13),U64(1),U64(2),Ref("DPD1",14),Ref("DCA1",15),B(64,16),Ref("XRA1",17)]);
        internal static readonly ContactRecord Xur = ContactCodecValidation.AuthorRecord("XUR1", [B(16,18),B(32,19),B(32,20),U64(0),new byte[32],Ref("PMT2",21),B(32,22),B(32,23),B(32,24),U16(7),U64(1),U64(2),B(32,25),Ref("DPD1",26),B(64,27)]);
        internal static readonly ContactRecord Pms = PmsRecord();
        internal static readonly ContactRecord Xrc = ContactCodecValidation.AuthorRecord("XRC1", [B(16,28),B(32,29),U64(0),new byte[32],Ref("XRA1",30),Ref("PMT2",31),B(32,32),Ref("XNV1",33),Ref("XNH1",34),B(32,35),B(32,36),B(32,37),U64(1),new byte[] { 2 },Rows(64,2,38),U64(1),U64(1),U64(2),Ref("ADH1",39),new byte[] { 2 },Rows(96,2,40)]);
        internal static readonly ContactRecord Xss = ContactCodecValidation.AuthorRecord("XSS1", [B(16,41),B(32,42),U64(1),B(32,43),Ref("XRC1",44),Ref("XRC1",45),Ref("PMT2",46),Ref("XNV1",47),B(32,48),U64(1),U64(2),Ref("ADH1",49),new byte[] { 2 },Rows(96,2,50)]);
        internal static readonly ContactRecord Xrr = ContactCodecValidation.AuthorRecord("XRR1", [B(16,51),B(32,52),U64(0),new byte[32],Ref("XRA1",53),Ref("XRC1",54),Ref("XSS1",55),Ref("PMT2",56),B(32,57),B(32,58),B(32,59),new byte[] { 1 },U32(1),U16(1),U64(1),U64(1),U64(2),Ref("DPD1",60),B(64,61),new byte[2]]);
        internal static readonly ContactRecord Dia = ContactCodecValidation.AuthorRecord("DIA1", [B(16,62),B(32,63),new byte[] { 2 },U16(1),B(16,64),B(32,65),B(32,66),U64(1),U16(1)]);
        internal static readonly ContactRecord Dcb = DcbRecord();
        internal static readonly ContactRecord Dcr = DcrRecord();
        internal static readonly (ContactRecord Xrr, ContactRecord Xra, ContactRecord Xrc, ContactRecord Xss, ContactRecord Pmt, ContactRecord Pms) RouteClosure = CreateRouteClosure(false);
        internal static readonly (ContactRecord Xrr, ContactRecord Xra, ContactRecord Xrc, ContactRecord Xss, ContactRecord Pmt, ContactRecord Pms) MaximumRouteClosure = CreateRouteClosure(true);
        internal static IEnumerable<ContactRecord> All() => [Dcb,Dcr,Dia,Xir,Xur,Xra,Pmt,Pms,Xrc,Xss,Xrr];

        private static (ContactRecord Xrr, ContactRecord Xra, ContactRecord Xrc, ContactRecord Xss, ContactRecord Pmt, ContactRecord Pms) CreateRouteClosure(bool maximum)
        {
            var pmt = maximum
                ? ContactCodecValidation.AuthorRecord("PMT2", [B(16,1),U64(0),new byte[32],Ref("PMA2",2),Ref("XNV1",3),U64(1),new byte[] { 5 },U16(56),Rows(136,56,4),U64(1),U64(1),U64(2),new byte[32],Ref("ADH1",5),new byte[] { 32 },Rows(96,32,6)])
                : Pmt;
            var xra = ContactCodecValidation.AuthorRecord("XRA1", [B(16,1),B(32,2),U64(0),new byte[32],ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes,B(32,3),U16(1),U32(1),B(32,4),B(32,5),B(32,6),U64(1),U64(2),B(32,7),Ref("DPD1",8),B(64,9)]);
            var pms = PmsFor(pmt, xra, maximum);
            var replicas = ReplicaEntries(pms);
            var xrc = ContactCodecValidation.AuthorRecord("XRC1", [B(16,1),B(32,10),U64(0),new byte[32],ContactCodec.ArtifactReference("XRA1", xra).CanonicalBytes,ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes,pms.ArtifactHash,pmt.Field(5),Ref("XNH1",12),B(32,13),xra.Field(10),xra.Field(11),U64(1),new byte[] { maximum ? (byte)5 : (byte)2 },replicas,U64(1),U64(1),U64(2),pmt.Field(14),new byte[] { maximum ? (byte)32 : (byte)2 },Rows(96,maximum ? 32 : 2,18)]);
            var xss = ContactCodecValidation.AuthorRecord("XSS1", [B(16,1),xrc.Field(2),U64(1),xrc.CoreHash,ContactCodec.ArtifactReference("XRC1", xrc).CanonicalBytes,ContactCodec.ArtifactReference("XRC1", xrc).CanonicalBytes,ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes,xrc.Field(8),pms.ArtifactHash,U64(1),U64(2),Ref("ADH1",23),new byte[] { maximum ? (byte)32 : (byte)2 },Rows(96,maximum ? 32 : 2,24)]);
            var xrr = ContactCodecValidation.AuthorRecord("XRR1", [B(16,1),B(32,25),U64(0),new byte[32],ContactCodec.ArtifactReference("XRA1", xra).CanonicalBytes,ContactCodec.ArtifactReference("XRC1", xrc).CanonicalBytes,ContactCodec.ArtifactReference("XSS1", xss).CanonicalBytes,ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes,pms.ArtifactHash,B(32,26),B(32,27),new byte[] { 1 },U32(1),U16(1),U64(1),U64(1),U64(2),xra.Field(15),B(64,29),new byte[2]]);
            return (xrr, xra, xrc, xss, pmt, pms);
        }

        private static ContactRecord DcbRecord()
        {
            var network = B(16, 72); var account = B(32, 73); var device = B(32, 74);
            var dpaFields = Minimum(RecordDefinitions.Dpa1); dpaFields[0] = network; dpaFields[1] = U64(1); dpaFields[2] = U64(1); dpaFields[4] = B(32,75); dpaFields[5] = B(32,76); dpaFields[6] = B(32,77); dpaFields[7] = B(32,78); dpaFields[8] = B(32,79); dpaFields[9] = U64(1); dpaFields[10] = U64(1); dpaFields[11] = U16(1);
            var dpa = CanonicalGrammar.Encode(RecordDefinitions.Dpa1, dpaFields);
            var dpaHash = IdentityCodec.DecodeAccountCertificate(dpa).CanonicalHash;
            var dpaReference = ApplicationCoreCodec.CreateArtifactReference(1, 644, dpaHash.Span);
            var dpd = DpdRecord(network, account, device);
            var dpdHash = IdentityCodec.DecodeDeviceCertificate(dpd).CanonicalHash;
            var dpdReference = ApplicationCoreCodec.CreateArtifactReference(2, 776, dpdHash.Span);
            var drs = ApplicationCoreFixture.Revocations(network, account);
            var drsReference = ApplicationCoreCodec.CreateArtifactReference(4,
                checked((uint)drs.CanonicalBytes.Length), drs.CanonicalHash.Span);
            var dmd = ApplicationCoreCodec.AuthorDmd1(network, account, 1, dpaReference, drsReference, 1, new byte[32], [new DeviceDirectoryEntry(device, dpdReference)], 100, B(64,84));
            var dab = ApplicationCoreCodec.AuthorDab1(B(32,85), B(32,86), 0, new byte[32], account, 1, dpaReference, B(64,87), B(64,88));
            var dabReference = ApplicationCoreCodec.CreateArtifactReference(ApplicationCoreCodec.Dab1ArtifactTypeCode, 394, B(32,80));
            var dca = ApplicationCoreCodec.AuthorDca1(network, account, dpaReference, 1, dmd.RecordHash.Span, B(32,81), device, 1, 1, 1, 2, B(64,82), B(32,83), dabReference);
            var xir = Xir.CanonicalBytes.ToArray(); var descriptor = new byte[651]; BinaryPrimitives.WriteUInt16BigEndian(descriptor,1); BinaryPrimitives.WriteUInt16BigEndian(descriptor.AsSpan(2),1); SHA256.HashData(xir).CopyTo(descriptor,4); BinaryPrimitives.WriteUInt32BigEndian(descriptor.AsSpan(36),611); xir.CopyTo(descriptor,40);
            var xps = Write("XPS1", [network,B(32,89),device,Ref("DPD1",90),U64(0),new byte[32],U16(0x0201),U16(1),U16(1),U64(1),U64(2),B(64,90)]); dpdHash.Span.CopyTo(xps.AsSpan(FieldOffset(xps,4)+6)); var xpsList = new byte[357]; xpsList[0]=1; BinaryPrimitives.WriteUInt32BigEndian(xpsList.AsSpan(1),352); xps.CopyTo(xpsList,5);
            var adl = AccountDirectoryAdl1Codec.Encode(new AccountDirectoryAdl1(
                network, B(32,90), 1, B(32,91), 1, new byte[38], new byte[32]));
            return ContactCodecValidation.AuthorRecord("DCB1", [network,account,dpa,Ref("DRS1",drs.CanonicalHash.Span),dmd.CanonicalBytes,dca.CanonicalBytes,B(32,88),U64(0),new byte[32],device,new byte[]{1},xpsList,new byte[]{1},descriptor,Array.Empty<byte>(),U32(3),U64(1),U64(2),B(64,89),adl,Join(U64(1),B(32,91)),B(32,92),B(32,93),dab.CanonicalBytes]);
        }

        private static ContactRecord DcrRecord()
        {
            var drs = ApplicationCoreFixture.Revocations(Dcb.Field(1).ToArray(), Dcb.Field(2).ToArray()).CanonicalBytes.ToArray();
            var dpd = DpdRecord(Dcb.Field(1).Span, Dcb.Field(2).Span, Dcb.Field(10).Span);
            var support = new byte[6+drs.Length+6+dpd.Length]; BinaryPrimitives.WriteUInt16BigEndian(support,1); BinaryPrimitives.WriteUInt32BigEndian(support.AsSpan(2),checked((uint)drs.Length)); drs.CopyTo(support,6); var offset=6+drs.Length; BinaryPrimitives.WriteUInt16BigEndian(support.AsSpan(offset),2); BinaryPrimitives.WriteUInt32BigEndian(support.AsSpan(offset+2),checked((uint)dpd.Length)); dpd.CopyTo(support,offset+6);
            return ContactCodecValidation.AuthorRecord("DCR1", [Dcb.Field(1),Dcb.CanonicalBytes,U16(2),support]);
        }
        private static ContactRecord PmsRecord()
        {
            var fields = new ReadOnlyMemory<byte>[] { B(16,67),Ref("PMT2",68),B(32,69),U64(1),new byte[] { 2 },Rows(32,2,70),new byte[32],U64(1),U64(2),new byte[] { 2 },Rows(96,2,71) };
            var provisional = Write("PMS2", fields); fields[6] = Sha256Selection(provisional); return ContactCodecValidation.AuthorRecord("PMS2", fields);
        }
        private static ContactRecord PmsFor(ContactRecord pmt, ContactRecord xra, bool maximum)
        {
            var replicaCount = maximum ? 5 : 2;
            var witnessCount = maximum ? 32 : 2;
            var ranked = RankedNodes(pmt, xra.Field(6));
            var fields = new ReadOnlyMemory<byte>[] { B(16,1),ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes,xra.Field(6),pmt.Field(6),new byte[] { (byte)replicaCount },ranked.AsMemory(0, replicaCount * 32),new byte[32],U64(1),U64(2),new byte[] { (byte)witnessCount },Rows(96,witnessCount,4) };
            var provisional = Write("PMS2", fields); fields[6] = Sha256Selection(provisional); return ContactCodecValidation.AuthorRecord("PMS2", fields);
        }
        private static byte[] Sha256Selection(byte[] encoded) { var projected=Project(encoded,[1,2,3,4,5,6]); var label=System.Text.Encoding.ASCII.GetBytes("Deep/XPoint/V1/PMS2/selection"); var input=new byte[label.Length+5+projected.Length]; label.CopyTo(input,0); BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(label.Length+1),checked((uint)projected.Length)); projected.CopyTo(input,label.Length+5); return SHA256.HashData(input); }
        private static byte[] RankedNodes(ContactRecord pmt, ReadOnlyMemory<byte> placementInput)
        {
            const string domain = "Deep/XPoint/V1/PMS2/rendezvous-sha256/v2";
            var nodes = pmt.Field(9).ToArray().Chunk(136).Select(row => row[..32]).ToArray();
            var reference = ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes.ToArray();
            var network = pmt.Field(1).ToArray(); var epoch = pmt.Field(6).ToArray();
            return nodes.Select(node => new { Node = node, Score = SHA256.HashData(Join(System.Text.Encoding.ASCII.GetBytes(domain), new byte[] { 0 }, network, reference, epoch, placementInput.ToArray(), node)) })
                .OrderBy(item => item.Score, ByteComparer.Instance).ThenBy(item => item.Node, ByteComparer.Instance)
                .SelectMany(item => item.Node).ToArray();
        }
        private static byte[] ReplicaEntries(ContactRecord pms)
        {
            var ranked = pms.Field(6).ToArray(); var entries = new byte[ranked.Length * 2];
            for (var index = 0; index < ranked.Length / 32; index++)
            {
                ranked.AsSpan(index * 32, 32).CopyTo(entries.AsSpan(index * 64, 32));
                B(32, (byte)(0x80 + index)).CopyTo(entries, index * 64 + 32);
            }
            return entries;
        }
        private static byte[] Rows(int width,int count,byte seed) { var bytes=new byte[width*count]; for(var i=0;i<count;i++) B(32,(byte)(seed+i)).CopyTo(bytes,i*width); return bytes; }
        private static byte[] DpdRecord(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> device) { var fields = Minimum(RecordDefinitions.Dpd1); fields[0] = network.ToArray(); fields[1] = account.ToArray(); fields[2] = U64(1); fields[3] = device.ToArray(); fields[4] = U64(1); fields[5] = B(32,80); fields[6] = B(32,81); fields[7] = B(32,82); fields[17] = U64(1); fields[18] = U16(1); return CanonicalGrammar.Encode(RecordDefinitions.Dpd1, fields); }
        private static ReadOnlyMemory<byte>[] Minimum(RecordDefinition definition) => definition.Fields.Select(field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();
        private static byte[] Canonical(string magic,int length) { var bytes=new byte[length]; System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(bytes,0); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4),1); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6),0x0201); return bytes; }
        private static byte[] Join(params byte[][] values) { var bytes=new byte[values.Sum(value=>value.Length)]; var offset=0; foreach(var value in values){value.CopyTo(bytes,offset);offset+=value.Length;} return bytes; }
        private static byte[] Write(string magic,IReadOnlyList<ReadOnlyMemory<byte>> fields) { var length=12+fields.Sum(f=>8+f.Length); var bytes=new byte[length]; System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(bytes,0); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4),1); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6),0x0201); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8),checked((ushort)fields.Count)); var offset=12; for(var i=0;i<fields.Count;i++){BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(offset),checked((ushort)(i+1)));BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset+4),checked((uint)fields[i].Length));offset+=8;fields[i].Span.CopyTo(bytes.AsSpan(offset));offset+=fields[i].Length;}return bytes; }
        private static byte[] Project(byte[] record,int[] tags) { var values=tags.Select(t=>record.AsSpan(FieldOffset(record,t),checked((int)BinaryPrimitives.ReadUInt32BigEndian(record.AsSpan(FieldOffset(record,t)-4,4)))).ToArray()).ToArray(); return Write("PMS2",tags.Select((tag,index)=>(ReadOnlyMemory<byte>)values[index]).ToArray()); }
        private sealed class ByteComparer : IComparer<byte[]>
        {
            internal static readonly ByteComparer Instance = new();
            public int Compare(byte[]? left, byte[]? right) => left is null ? (right is null ? 0 : -1) : right is null ? 1 : left.AsSpan().SequenceCompareTo(right);
        }
    }

    private sealed class Resolver(params ContactRecord[] records) : IContactRecordResolver
    {
        private readonly Dictionary<string, ContactRecord> items = records.ToDictionary(record => Convert.ToHexString(record.ArtifactHash.Span));
        public ContactRecord? Resolve(ContactArtifactReference reference) => items.GetValueOrDefault(Convert.ToHexString(reference.Hash.Span));
    }
}
