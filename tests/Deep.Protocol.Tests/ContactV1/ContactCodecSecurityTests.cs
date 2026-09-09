using System.Buffers.Binary;
using System.Diagnostics;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Tests.ApplicationCore;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.ContactV1;

[Collection("Production artifact build")]
public sealed class ContactCodecSecurityTests
{
    [Fact]
    public void RoutePromotionUsesRealEd25519AndRejectsPolicyMutations()
    {
        var fixture = CryptoRouteFixture.Create();

        Assert.True(PublicKeyAuth.VerifyDetached(fixture.Xir.Field(17).ToArray(), fixture.Xir.SignatureInput.ToArray(), fixture.Device.PublicKey));
        Assert.True(PublicKeyAuth.VerifyDetached(fixture.Xra.Field(16).ToArray(), fixture.Xra.SignatureInput.ToArray(), fixture.Device.PublicKey));
        Assert.True(PublicKeyAuth.VerifyDetached(fixture.Xrr.Field(19).ToArray(), fixture.Xrr.SignatureInput.ToArray(), fixture.Device.PublicKey));
        foreach (var record in new[] { fixture.Pmt, fixture.Pms, fixture.Xrc, fixture.Xss })
            fixture.AssertIndependentWitnessSignatures(record);

        var verified = ContactCodec.VerifyRouteUpdateClosure(
            fixture.Xir, fixture.Xrr, fixture.Xra, fixture.Xrc, fixture.Xss,
            fixture.Pmt, fixture.Pms, fixture.Authority);
        Assert.Same(fixture.Xrr, verified.Reachability);

        var changedPolicy = fixture.ResignDevice(fixture.Xrr, 11, Bytes(32, 0xe1), 19);
        var policy = Assert.Throws<ContactFormatException>(() => ContactCodec.VerifyRouteUpdateClosure(
            fixture.Xir, changedPolicy, fixture.Xra, fixture.Xrc, fixture.Xss,
            fixture.Pmt, fixture.Pms, fixture.Authority));
        Assert.Equal("InviteRouteAuthorityMismatch", policy.Code);

        var stale = fixture.ResignDevice(fixture.Xrr, 17, U64(25), 19);
        var time = Assert.Throws<ContactFormatException>(() => ContactCodec.VerifyRouteUpdateClosure(
            fixture.Xir, stale, fixture.Xra, fixture.Xrc, fixture.Xss,
            fixture.Pmt, fixture.Pms, fixture.Authority));
        Assert.Equal("RouteNotCurrentAtTrustedTime", time.Code);

        var forgedBytes = fixture.Xir.CanonicalBytes.ToArray();
        forgedBytes[FieldOffset(forgedBytes, 17)] ^= 1;
        var forged = ContactCodec.Decode("XIR1", forgedBytes);
        var signature = Assert.Throws<ContactFormatException>(() => ContactCodec.VerifyRouteUpdateClosure(
            forged, fixture.Xrr, fixture.Xra, fixture.Xrc, fixture.Xss,
            fixture.Pmt, fixture.Pms, fixture.Authority));
        Assert.Equal(ContactValidationStage.Signature, signature.Stage);
    }

    [Fact]
    public void PublicSurfaceHasNoCallerVerifierOrForgeableCapabilityConstructor()
    {
        Assert.Null(typeof(ContactCodec).Assembly.GetType("Deep.Protocol.ContactV1.IContactSignatureVerifier"));
        var promotion = typeof(ContactCodec).GetMethod(nameof(ContactCodec.VerifyRouteUpdateClosure));
        Assert.NotNull(promotion);
        Assert.Equal(typeof(VerifiedContactRouteClosure), promotion!.ReturnType);
        Assert.Contains(promotion.GetParameters(), parameter => parameter.ParameterType == typeof(VerifiedContactNetworkAuthority));
        Assert.Empty(typeof(VerifiedContactNetworkAuthority).GetConstructors());
        Assert.Empty(typeof(VerifiedAccountDirectoryFreshness).GetConstructors());
    }

    [Fact]
    public void DcrPromotionExecutesIdentityGenerationAndFreshnessNegatives()
    {
        var fixture = CryptoDcrFixture.Create();
        var verified = fixture.Promote(fixture.Dcr);
        Assert.Equal(fixture.Bundle.CanonicalBytes.ToArray(), verified.Bundle.CanonicalBytes.ToArray());
        Assert.True(PublicKeyAuth.VerifyDetached(fixture.Bundle.Field(19).ToArray(), fixture.Bundle.SignatureInput.ToArray(), fixture.Device.PublicKey));

        var generationFields = fixture.BundleFields();
        generationFields[7] = U64(6);
        generationFields[8] = Bytes(32, 0xf0);
        var generation = fixture.DcrFor(fixture.SignBundle(generationFields));
        var generationError = Assert.Throws<ContactFormatException>(() => fixture.Promote(generation));
        Assert.Equal("ContactPublicationPolicyMismatch", generationError.Code);

        var didFields = fixture.BundleFields();
        didFields[21] = Bytes(32, 0xe0);
        var did = fixture.DcrFor(fixture.SignBundle(didFields));
        var didError = Assert.Throws<ContactFormatException>(() => fixture.Promote(did));
        Assert.Equal("DirectoryFreshnessIdentityMismatch", didError.Code);

        var staleFields = fixture.BundleFields();
        var xpsList = staleFields[11].ToArray();
        var xps = xpsList.AsSpan(5, 352).ToArray();
        BinaryPrimitives.WriteUInt64BigEndian(xps.AsSpan(FieldOffset(xps, 11), 8), 25);
        var projection = ProjectRaw(xps, 11);
        PublicKeyAuth.SignDetached(ContactCodec.SignatureInput("Deep/ContactResolver/V1/prekey-service", projection), fixture.Device.PrivateKey)
            .CopyTo(xps, FieldOffset(xps, 12));
        xps.CopyTo(xpsList, 5); staleFields[11] = xpsList;
        var stale = fixture.DcrFor(fixture.SignBundle(staleFields));
        var staleError = Assert.Throws<ContactFormatException>(() => fixture.Promote(stale));
        Assert.Equal("Xps1ValidityDoesNotCoverAuthenticatedTime", staleError.Code);

        var expiredFreshness = Assert.Throws<ContactFormatException>(() => fixture.Promote(
            fixture.Dcr, currentMonotonicSample: fixture.Freshness.FreshnessDeadlineMonotonicSeconds));
        Assert.Equal("DirectoryFreshnessExpired", expiredFreshness.Code);

        var wrongBoot = Assert.Throws<ContactFormatException>(() => fixture.Promote(
            fixture.Dcr, bootId: Bytes(16, 0xee)));
        Assert.Equal("DirectoryFreshnessExpired", wrongBoot.Code);

        var floorFields = fixture.BundleFields();
        var lookup = AccountDirectoryAdl1Codec.Decode(floorFields[19].Span);
        var olderFloorFields = fixture.BundleFields();
        olderFloorFields[19] = AccountDirectoryAdl1Codec.Encode(new AccountDirectoryAdl1(
            lookup.NetworkId.Span, lookup.DirectoryLookupKey.Span, 0, Bytes(32, 0xa7),
            lookup.ServiceProfile, lookup.ExactOhttpXod1CoreReference.Span,
            lookup.ExactOhttpXod1CoreHash.Span));
        olderFloorFields[20] = U64(0).Concat(Bytes(32, 0xa7)).ToArray();
        var newerThanFloor = fixture.Promote(
            fixture.DcrFor(fixture.SignBundle(olderFloorFields)));
        Assert.Equal(fixture.Freshness.AdhGeneration, newerThanFloor.Freshness.AdhGeneration);

        floorFields[19] = AccountDirectoryAdl1Codec.Encode(new AccountDirectoryAdl1(
            lookup.NetworkId.Span, lookup.DirectoryLookupKey.Span,
            checked(lookup.MinimumAdhGeneration + 1), lookup.MinimumAdhHash.Span,
            lookup.ServiceProfile, lookup.ExactOhttpXod1CoreReference.Span,
            lookup.ExactOhttpXod1CoreHash.Span));
        floorFields[20] = U64(checked(lookup.MinimumAdhGeneration + 1))
            .Concat(lookup.MinimumAdhHash.ToArray()).ToArray();
        var floorError = Assert.Throws<ContactFormatException>(() => fixture.Promote(
            fixture.DcrFor(fixture.SignBundle(floorFields))));
        Assert.Equal("DirectoryFreshnessIdentityMismatch", floorError.Code);

        var mismatchedSignedFloors = fixture.BundleFields();
        mismatchedSignedFloors[19] = AccountDirectoryAdl1Codec.Encode(new AccountDirectoryAdl1(
            lookup.NetworkId.Span, lookup.DirectoryLookupKey.Span, 0, Bytes(32, 0xa7),
            lookup.ServiceProfile, lookup.ExactOhttpXod1CoreReference.Span,
            lookup.ExactOhttpXod1CoreHash.Span));
        var mismatchError = Assert.Throws<ContactFormatException>(() => fixture.Promote(
            fixture.DcrFor(fixture.SignBundle(mismatchedSignedFloors))));
        Assert.Equal("ApplicationClosureMismatch", mismatchError.Code);

        var wrongLeafKey = lookup.DirectoryLookupKey.ToArray();
        wrongLeafKey[^1] ^= 1;
        var leafFields = fixture.BundleFields();
        leafFields[19] = AccountDirectoryAdl1Codec.Encode(new AccountDirectoryAdl1(
            lookup.NetworkId.Span, wrongLeafKey, lookup.MinimumAdhGeneration,
            lookup.MinimumAdhHash.Span, lookup.ServiceProfile,
            lookup.ExactOhttpXod1CoreReference.Span, lookup.ExactOhttpXod1CoreHash.Span));
        var leafError = Assert.Throws<ContactFormatException>(() => fixture.Promote(
            fixture.DcrFor(fixture.SignBundle(leafFields))));
        Assert.Equal("DirectoryFreshnessIdentityMismatch", leafError.Code);

        var hashFields = fixture.BundleFields();
        hashFields[19] = AccountDirectoryAdl1Codec.Encode(new AccountDirectoryAdl1(
            lookup.NetworkId.Span, lookup.DirectoryLookupKey.Span,
            fixture.Freshness.AdhGeneration, Bytes(32, 0xa8), lookup.ServiceProfile,
            lookup.ExactOhttpXod1CoreReference.Span, lookup.ExactOhttpXod1CoreHash.Span));
        hashFields[20] = U64(fixture.Freshness.AdhGeneration)
            .Concat(Bytes(32, 0xa8)).ToArray();
        var hashError = Assert.Throws<ContactFormatException>(() => fixture.Promote(
            fixture.DcrFor(fixture.SignBundle(hashFields))));
        Assert.Equal("DirectoryFreshnessIdentityMismatch", hashError.Code);

        var revoked = CryptoDcrFixture.Create(revokeAuthorization: true);
        var revokedError = Assert.Throws<ContactFormatException>(() => revoked.Promote(revoked.Dcr));
        Assert.Equal("DcaAuthorizationRevoked", revokedError.Code);

        var narrowDca = CryptoDcrFixture.Create(dcaExpiresAt: 31);
        var dcaIntervalError = Assert.Throws<ContactFormatException>(() =>
            narrowDca.Promote(narrowDca.Dcr));
        Assert.Equal("ContactValidityDoesNotCoverAuthenticatedTime", dcaIntervalError.Code);

        var narrowBundleFields = fixture.BundleFields();
        narrowBundleFields[17] = U64(31);
        var bundleIntervalError = Assert.Throws<ContactFormatException>(() => fixture.Promote(
            fixture.DcrFor(fixture.SignBundle(narrowBundleFields))));
        Assert.Equal("ContactValidityDoesNotCoverAuthenticatedTime", bundleIntervalError.Code);

        var xirIntervalError = Assert.Throws<ContactFormatException>(() => fixture.Promote(
            fixture.DcrWithXirExpiry(31)));
        Assert.Equal("ContactValidityDoesNotCoverAuthenticatedTime", xirIntervalError.Code);

        var substituted = CryptoDcrFixture.Create(variant: 1);
        var substitutionError = Assert.Throws<ContactFormatException>(() =>
            fixture.PromoteWithFreshness(fixture.Dcr, substituted.Freshness));
        Assert.Equal("VerifiedIdentityClosureMismatch", substitutionError.Code);

        var executed = new HashSet<string>(StringComparer.Ordinal);
        ExecuteDcrPolicyNegatives(fixture, executed);
        ExecuteRoutePolicyNegatives(CryptoRouteFixture.Create(), executed);
        AssertDeclaredPolicyNegativesExecuted(executed);
    }

    [Fact]
    public void ProductionArtifactHasNoTestFriendOrTestSeamMetadata()
    {
        var root = FindRepositoryRoot();
        var output = Path.Combine(Path.GetTempPath(), "deep-contact-production-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(output);
        try
        {
            var start = new ProcessStartInfo("dotnet")
            {
                WorkingDirectory = root,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            foreach (var argument in new[]
            {
                "build", Path.Combine(root, "src", "Deep.Protocol", "Deep.Protocol.csproj"),
                "-c", "Release", "--no-restore", "-p:RecoveryTestSeam=false", "-o", output,
            }) start.ArgumentList.Add(argument);
            using var process = Process.Start(start) ?? throw new InvalidOperationException("dotnet build did not start.");
            var stdout = process.StandardOutput.ReadToEnd();
            var stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();
            Assert.True(process.ExitCode == 0, stdout + Environment.NewLine + stderr);

            using var stream = File.OpenRead(Path.Combine(output, "Deep.Protocol.dll"));
            using var pe = new PEReader(stream);
            var metadata = pe.GetMetadataReader();
            var productionFriends = metadata.GetAssemblyDefinition().GetCustomAttributes()
                .Where(handle => AttributeTypeName(metadata, handle) ==
                    "System.Runtime.CompilerServices.InternalsVisibleToAttribute")
                .Select(handle => AttributeStringArgument(metadata, handle))
                .ToArray();
            Assert.Empty(productionFriends);
            Assert.DoesNotContain(metadata.TypeDefinitions, handle =>
            {
                var type = metadata.GetTypeDefinition(handle);
                return metadata.GetString(type.Namespace) == "Deep.Protocol.ContactV1" &&
                    metadata.GetString(type.Name) == "ContactCodecValidation";
            });
            Assert.DoesNotContain(metadata.TypeDefinitions.SelectMany(handle =>
                metadata.GetTypeDefinition(handle).GetMethods()), handle =>
                metadata.GetString(metadata.GetMethodDefinition(handle).Name).EndsWith("ForValidation", StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(output, recursive: true);
        }
    }

    private static string AttributeTypeName(MetadataReader metadata, CustomAttributeHandle handle)
    {
        var attribute = metadata.GetCustomAttribute(handle);
        if (attribute.Constructor.Kind != HandleKind.MemberReference) return string.Empty;
        var member = metadata.GetMemberReference((MemberReferenceHandle)attribute.Constructor);
        if (member.Parent.Kind != HandleKind.TypeReference) return string.Empty;
        var type = metadata.GetTypeReference((TypeReferenceHandle)member.Parent);
        return metadata.GetString(type.Namespace) + "." + metadata.GetString(type.Name);
    }

    private static string AttributeStringArgument(
        MetadataReader metadata,
        CustomAttributeHandle handle)
    {
        var reader = metadata.GetBlobReader(metadata.GetCustomAttribute(handle).Value);
        Assert.Equal((ushort)1, reader.ReadUInt16());
        return reader.ReadSerializedString() ?? string.Empty;
    }

    private static string FindRepositoryRoot()
    {
        for (var path = Directory.GetCurrentDirectory(); path is not null; path = Directory.GetParent(path)?.FullName)
            if (File.Exists(Path.Combine(path, "Deep.Protocol.slnx"))) return path;
        throw new DirectoryNotFoundException("Deep.Protocol.slnx");
    }

    private static void ExecuteDcrPolicyNegatives(CryptoDcrFixture fixture, HashSet<string> executed)
    {
        var (drs, dpd) = fixture.SupportObjects();
        Reject("dcr-missing-support", () => fixture.DcrFor(fixture.Bundle, 1, Support((1, drs))), executed);
        Reject("dcr-extra-support", () => fixture.DcrFor(fixture.Bundle, 3,
            Support((1, drs), (2, dpd), (2, dpd))), executed);
        Reject("dcr-duplicate-support", () => fixture.DcrFor(fixture.Bundle, 2,
            Support((1, drs), (1, drs))), executed);
        Reject("dcr-reordered-support", () => fixture.DcrFor(fixture.Bundle, 2,
            Support((2, dpd), (1, drs))), executed);

        var alternateDrs = ApplicationCoreFixture.Revocations(
            fixture.Bundle.Field(1).ToArray(), Bytes(32, 0xd1));
        var drsFields = fixture.BundleFields();
        drsFields[3] = Ref("DRS1", alternateDrs.CanonicalHash.Span);
        var alternateDrsBundle = fixture.SignBundle(drsFields);
        Reject("dcr-unverified-drs", () => fixture.Promote(fixture.DcrFor(alternateDrsBundle, 2,
            Support((1, alternateDrs.CanonicalBytes.ToArray()), (2, dpd)))), executed);
        Reject("dcr-unverified-dpd", () => fixture.Promote(fixture.DcrWithUnverifiedDpd()), executed);

        var badBundleBytes = fixture.Bundle.CanonicalBytes.ToArray();
        badBundleBytes[FieldOffset(badBundleBytes, 19)] ^= 1;
        var badBundle = ContactCodec.Decode("DCB1", badBundleBytes);
        Reject("dcb-invalid-signature", () => fixture.Promote(fixture.DcrFor(badBundle)), executed);

        var xpsFields = fixture.BundleFields();
        var xpsList = xpsFields[11].ToArray();
        var xpsOffset = 5;
        xpsList[xpsOffset + FieldOffset(xpsList.AsSpan(xpsOffset), 12)] ^= 1;
        xpsFields[11] = xpsList;
        Reject("xps-invalid-signature", () => fixture.Promote(
            fixture.DcrFor(fixture.SignBundle(xpsFields))), executed);

        var utf8Fields = fixture.BundleFields();
        utf8Fields[14] = new byte[] { 0xc0, 0x80 };
        Reject("invalid-profile-utf8", () => fixture.SignBundle(utf8Fields), executed);

        Reject("dcr-support-overflow", () => ContactCodecValidation.AuthorRecord("DCR1", [
            fixture.Dcr.Field(1), fixture.Dcr.Field(2), U16(2), new byte[16_385]]), executed);
    }

    private static void ExecuteRoutePolicyNegatives(CryptoRouteFixture fixture, HashSet<string> executed)
    {
        var wrongInvite = fixture.ResignDevice(fixture.Xir, 18, Ref("XRA1", Bytes(32, 0xc1)), 17);
        Reject("xir-xra-binding", () => PromoteRoute(fixture, wrongInvite, fixture.Xrr,
            fixture.Xrc, fixture.Pms), executed);

        var wrongSealing = fixture.ResignWitness(fixture.Xrc, 11, Bytes(32, 0xc2), 21);
        var sealingXrr = fixture.ResignDevice(fixture.Xrr, 6,
            ContactCodec.ArtifactReference("XRC1", wrongSealing).CanonicalBytes.ToArray(), 19);
        Reject("xrc-xra-sealing-binding", () => PromoteRoute(fixture, fixture.Xir, sealingXrr,
            wrongSealing, fixture.Pms), executed);

        var wrongXnv = fixture.ResignWitness(fixture.Xrc, 8, Ref("XNV1", Bytes(32, 0xc3)), 21);
        var xnvXrr = fixture.ResignDevice(fixture.Xrr, 6,
            ContactCodec.ArtifactReference("XRC1", wrongXnv).CanonicalBytes.ToArray(), 19);
        Reject("xrc-pmt-xnv-binding", () => PromoteRoute(fixture, fixture.Xir, xnvXrr,
            wrongXnv, fixture.Pms), executed);

        var wrongDevice = fixture.ResignDevice(fixture.Xrr, 18, Ref("DPD1", Bytes(32, 0xc4)), 19);
        Reject("xrr-device-binding", () => PromoteRoute(fixture, fixture.Xir, wrongDevice,
            fixture.Xrc, fixture.Pms), executed);

        var stale = fixture.ResignDevice(fixture.Xrr, 17, U64(25), 19);
        Reject("route-validity-intersection", () => PromoteRoute(fixture, fixture.Xir, stale,
            fixture.Xrc, fixture.Pms), executed);

        var minimumReaderBytes = fixture.Xrr.CanonicalBytes.ToArray();
        Array.Clear(minimumReaderBytes, FieldOffset(minimumReaderBytes, 14), 2);
        Reject("xrr-minimum-reader-zero", () => ContactCodec.Decode("XRR1", minimumReaderBytes), executed);

        var reversedPms = fixture.ReversePmsSelection();
        var selectionXrr = fixture.ResignDevice(fixture.Xrr, 9,
            reversedPms.ArtifactHash.ToArray(), 19);
        Reject("pms-tie-break", () => PromoteRoute(fixture, fixture.Xir, selectionXrr,
            fixture.Xrc, reversedPms), executed);
    }

    private static VerifiedContactRouteClosure PromoteRoute(CryptoRouteFixture fixture,
        ContactRecord xir, ContactRecord xrr, ContactRecord xrc, ContactRecord pms) =>
        ContactCodec.VerifyRouteUpdateClosure(xir, xrr, fixture.Xra, xrc, fixture.Xss,
            fixture.Pmt, pms, fixture.Authority);

    private static void Reject(string id, Action action, HashSet<string> executed)
    {
        Assert.Throws<ContactFormatException>(action);
        Assert.True(executed.Add(id), $"Policy negative '{id}' executed more than once.");
    }

    private static void AssertDeclaredPolicyNegativesExecuted(HashSet<string> executed)
    {
        var path = Path.Combine(FindRepositoryRoot(), "..", "docs", "survival-program", "releases",
            "v3.0.0", "specs", "contact-codec-v1.vectors.json");
        using var document = JsonDocument.Parse(File.ReadAllBytes(path));
        var declared = document.RootElement.GetProperty("negativeCases").EnumerateArray()
            .Select(item => item.GetProperty("id").GetString()!)
            .Order(StringComparer.Ordinal).ToArray();
        Assert.Equal(declared, executed.Order(StringComparer.Ordinal).ToArray());
    }

    private static byte[] Support(params (ushort Kind, byte[] Canonical)[] entries)
    {
        var output = new byte[entries.Sum(entry => 6 + entry.Canonical.Length)];
        var offset = 0;
        foreach (var entry in entries)
        {
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), entry.Kind);
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset + 2), checked((uint)entry.Canonical.Length));
            entry.Canonical.CopyTo(output, offset + 6);
            offset += 6 + entry.Canonical.Length;
        }
        return output;
    }

    private static int FieldOffset(ReadOnlySpan<byte> bytes, int sought)
    {
        var offset = 12; var count = BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(8, 2));
        for (var index = 0; index < count; index++)
        {
            var tag = BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(offset, 2));
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(offset + 4, 4)));
            offset += 8; if (tag == sought) return offset; offset += length;
        }
        throw new InvalidOperationException();
    }

    private static byte[] Bytes(int length, byte seed) =>
        Enumerable.Range(0, length).Select(index => unchecked((byte)(seed + index))).ToArray();
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
    private static byte[] U32(uint value) { var bytes = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(bytes, value); return bytes; }
    private static byte[] U16(ushort value) { var bytes = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); return bytes; }
    private static byte[] Ref(string magic, byte seed) { var bytes = new byte[38]; Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1); Bytes(32, seed).CopyTo(bytes, 6); return bytes; }
    private static byte[] Ref(string magic, ReadOnlySpan<byte> hash) { var bytes = new byte[38]; Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1); hash.CopyTo(bytes.AsSpan(6)); return bytes; }

    private static byte[] ProjectRaw(ReadOnlySpan<byte> canonical, int fields)
    {
        var end = 12;
        for (var index = 0; index < fields; index++) end += 8 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(canonical.Slice(end + 4, 4)));
        var output = canonical[..end].ToArray(); BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8), checked((ushort)fields)); return output;
    }

    internal sealed class CryptoDcrFixture
    {
        private readonly byte variant;
        private readonly ulong trustedUnixSeconds;
        private readonly bool revokeAuthorization;
        private readonly ulong dcaExpiresAt;
        private readonly byte[]? networkOverride;
        private CryptoDcrFixture(
            byte variant,
            ulong trustedUnixSeconds,
            bool revokeAuthorization,
            ulong dcaExpiresAt,
            byte[]? networkOverride)
        {
            this.variant = variant;
            this.trustedUnixSeconds = trustedUnixSeconds;
            this.revokeAuthorization = revokeAuthorization;
            this.dcaExpiresAt = dcaExpiresAt;
            this.networkOverride = networkOverride?.ToArray();
        }
        internal KeyPair Device { get; private set; } = null!;
        internal ContactRecord Bundle { get; private set; } = null!;
        internal ContactRecord Dcr { get; private set; } = null!;
        internal VerifiedDab1 Binding { get; private set; } = null!;
        internal VerifiedDmd1 Directory { get; private set; } = null!;
        internal CurrentlyAuthoritativeDca1 Authorization { get; private set; } = null!;
        internal VerifiedDevice VerifiedRecipient { get; private set; } = null!;
        internal VerifiedXPointNetworkAuthority NetworkAuthority { get; private set; } = null!;
        internal IReadOnlyList<Witness> NetworkWitnesses { get; private set; } = null!;
        internal VerifiedAccountDirectoryFreshness Freshness { get; private set; } = null!;
        internal byte[] BootId { get; } = Bytes(16, 0x44);
        internal ulong CurrentMonotonicSample { get; } = 1_003;
        internal byte[] Adc { get; private set; } = null!;
        internal byte[] Adh { get; private set; } = null!;
        internal byte[] Adp { get; private set; } = null!;
        internal byte[] Drs => drs.ToArray();
        internal byte[] Dpd => dpd.ToArray();
        private byte[] drs = null!, dpd = null!;

        internal static CryptoDcrFixture Create(
            byte variant = 0,
            ulong trustedUnixSeconds = 30,
            bool revokeAuthorization = false,
            ulong dcaExpiresAt = 90,
            byte[]? networkId = null)
        {
            var value = new CryptoDcrFixture(
                variant, trustedUnixSeconds, revokeAuthorization, dcaExpiresAt, networkId);
            value.Build();
            return value;
        }

        private void Build()
        {
            Device = PublicKeyAuth.GenerateKeyPair(Bytes(32, unchecked((byte)(0xb0 + variant))));
            var addressKey = PublicKeyAuth.GenerateKeyPair(Bytes(32, unchecked((byte)(0x81 + variant))));
            var accountKey = PublicKeyAuth.GenerateKeyPair(Bytes(32, unchecked((byte)(0x82 + variant))));
            var deviceIssuerKey = PublicKeyAuth.GenerateKeyPair(Bytes(32, unchecked((byte)(0x83 + variant))));
            var revocationKey = PublicKeyAuth.GenerateKeyPair(Bytes(32, unchecked((byte)(0x84 + variant))));
            var resetKey = PublicKeyAuth.GenerateKeyPair(Bytes(32, unchecked((byte)(0x85 + variant))));
            var network = networkOverride?.ToArray() ?? Bytes(16, 0x11);
            var accountHash = Bytes(32, unchecked((byte)(0x22 + variant)));
            var deviceId = Bytes(32, unchecked((byte)(0x33 + variant)));

            var dpaFields = MinimumFields(RecordDefinitions.Dpa1);
            dpaFields[0] = network;
            dpaFields[1] = U64(1);
            dpaFields[2] = U64(1);
            dpaFields[4] = accountKey.PublicKey;
            dpaFields[5] = deviceIssuerKey.PublicKey;
            dpaFields[6] = revocationKey.PublicKey;
            dpaFields[7] = resetKey.PublicKey;
            dpaFields[8] = Bytes(32, 0x44);
            dpaFields[9] = U64(10);
            dpaFields[10] = U64(1);
            dpaFields[11] = U16(ArtifactRegistry.IdentityAuthV1Ed25519);
            var accountCertificate = IdentityCodec.DecodeAccountCertificate(
                CanonicalGrammar.Encode(RecordDefinitions.Dpa1, dpaFields));
            var verifiedAccount = new VerifiedAccount(accountCertificate, accountHash);

            var revocationSnapshot = ApplicationCoreFixture.Revocations(network, accountHash);
            drs = revocationSnapshot.CanonicalBytes.ToArray();
            var revocations = new VerifiedRevocationState(verifiedAccount, revocationSnapshot, new RevocationCatalog([]));
            var dpaRef = AppRef(accountCertificate);
            var drsRef = AppRef(revocationSnapshot);

            var dpdFields = MinimumFields(RecordDefinitions.Dpd1);
            dpdFields[0] = network;
            dpdFields[1] = accountHash;
            dpdFields[2] = U64(1);
            dpdFields[3] = deviceId;
            dpdFields[4] = U64(1);
            dpdFields[5] = Device.PublicKey;
            dpdFields[6] = Bytes(32, 0x51);
            dpdFields[7] = Bytes(32, 0x52);
            dpdFields[8] = U64(1);
            dpdFields[10] = Bytes(32, 0x53);
            dpdFields[11] = U64(revocationSnapshot.Revision);
            dpdFields[12] = drsRef.CanonicalBytes;
            dpdFields[13] = U64(revocationSnapshot.EntryCount);
            dpdFields[14] = revocationSnapshot.CurrentHead;
            dpdFields[15] = U64(10);
            dpdFields[16] = U64(1_000);
            dpdFields[17] = U64((ulong)DeviceCapabilities.MailboxRoleIssuer);
            dpdFields[18] = U16(ArtifactRegistry.IdentityAuthV1Ed25519);
            dpdFields[20] = Bytes(32, 0x55);
            var deviceCertificate = IdentityCodec.DecodeDeviceCertificate(
                CanonicalGrammar.Encode(RecordDefinitions.Dpd1, dpdFields));
            dpd = deviceCertificate.CanonicalBytes.ToArray();
            var verifiedDevice = new VerifiedDevice(deviceCertificate, revocations,
                new X25519Possession(X25519PossessionRole.Device, dpdFields[20].Span));
            VerifiedRecipient = verifiedDevice;
            var identity = ApplicationCoreVerifier.CreateIdentityClosure(
                verifiedAccount, revocations, [verifiedDevice]);

            var dpdRef = AppRef(deviceCertificate);
            var did = ApplicationCoreCodec.AuthorDid1(addressKey.PublicKey, Bytes(16, 0x66));
            var realm = ApplicationCoreCodec.DeriveIdentityRealmId(network, 7);
            var unsignedDab = ApplicationCoreCodec.AuthorDab1(did.RecordHash.Span, realm.Span, 0,
                new byte[32], accountHash, 1, dpaRef, new byte[64], new byte[64]);
            var dab = ApplicationCoreCodec.AuthorDab1(did.RecordHash.Span, realm.Span, 0,
                new byte[32], accountHash, 1, dpaRef,
                PublicKeyAuth.SignDetached(unsignedDab.AddressSignatureInput.ToArray(), addressKey.PrivateKey),
                PublicKeyAuth.SignDetached(unsignedDab.AccountSignatureInput.ToArray(), accountKey.PrivateKey));
            Binding = ApplicationCoreVerifier.VerifyDab1(dab, did, identity, 7);

            var directoryEntry = new DeviceDirectoryEntry(deviceId, dpdRef);
            var unsignedDmd = ApplicationCoreCodec.AuthorDmd1(network, accountHash, 1, dpaRef, drsRef,
                1, new byte[32], [directoryEntry], 20, new byte[64]);
            var dmd = ApplicationCoreCodec.AuthorDmd1(network, accountHash, 1, dpaRef, drsRef,
                1, new byte[32], [directoryEntry], 20,
                PublicKeyAuth.SignDetached(unsignedDmd.SignatureInput.ToArray(), deviceIssuerKey.PrivateKey));
            Directory = ApplicationCoreVerifier.VerifyDmd1(dmd, identity);

            var dabRef = ApplicationCoreCodec.CreateArtifactReference(ApplicationCoreCodec.Dab1ArtifactTypeCode,
                checked((uint)dab.CanonicalBytes.Length), dab.RecordHash.Span);
            var unsignedDca = ApplicationCoreCodec.AuthorDca1(network, accountHash, dpaRef, 1,
                dmd.RecordHash.Span, Bytes(32, 0x47), deviceId, 3, 5, 20, dcaExpiresAt,
                new byte[64], did.RecordHash.Span, dabRef);
            var dca = ApplicationCoreCodec.AuthorDca1(network, accountHash, dpaRef, 1,
                dmd.RecordHash.Span, Bytes(32, 0x47), deviceId, 3, 5, 20, dcaExpiresAt,
                PublicKeyAuth.SignDetached(unsignedDca.SignatureInput.ToArray(), accountKey.PrivateKey),
                did.RecordHash.Span, dabRef);
            Authorization = ApplicationCoreVerifier.RequireDca1CurrentlyAuthoritative(
                ApplicationCoreVerifier.VerifyDca1(dca, Binding, Directory), trustedUnixSeconds);
            var contactDpdRef = Ref("DPD1", deviceCertificate.CanonicalHash.Span);
            var contactDcaRef = Ref("DCA1", dca.RecordHash.Span);

            var xpsFields = new ReadOnlyMemory<byte>[] { network,Bytes(32,0x49),deviceCertificate.DeviceId,contactDpdRef,U64(1),Bytes(32,0x48),U16(0x0201),U16(1),U16(1),U64(20),U64(90),Bytes(64,0x4a) };
            var xps = Write("XPS1", xpsFields); var xpsProjection = ProjectRaw(xps, 11);
            xpsFields[11] = PublicKeyAuth.SignDetached(ContactCodec.SignatureInput("Deep/ContactResolver/V1/prekey-service", xpsProjection), Device.PrivateKey);
            xps = Write("XPS1", xpsFields); var xpsList = new byte[357]; xpsList[0] = 1; BinaryPrimitives.WriteUInt32BigEndian(xpsList.AsSpan(1), 352); xps.CopyTo(xpsList, 5);

            var pmtRef = Ref("PMT2", Bytes(32, 0x60));
            var xirFields = new ReadOnlyMemory<byte>[] { network,Bytes(32,0x4b),U64(0),new byte[32],pmtRef,Bytes(32,0x4c),Bytes(32,0x4d),Bytes(32,0x4e),new byte[]{1},U32(0),U16(2),Bytes(32,0x4f),U64(20),U64(90),contactDpdRef,contactDcaRef,Bytes(64,0x50),Ref("XRA1",0x51) };
            var xir = DeviceRecord("XIR1", xirFields, 17);
            var descriptor = new byte[651]; BinaryPrimitives.WriteUInt16BigEndian(descriptor, 1); BinaryPrimitives.WriteUInt16BigEndian(descriptor.AsSpan(2), 1); SHA256.HashData(xir.CanonicalBytes.Span).CopyTo(descriptor, 4); BinaryPrimitives.WriteUInt32BigEndian(descriptor.AsSpan(36), 611); xir.CanonicalBytes.Span.CopyTo(descriptor.AsSpan(40));
            ReadOnlyMemory<byte>[] revoked = revokeAuthorization ? [dca.AuthorizationId] : [];
            var directoryLeaf = AccountDirectoryAdc1Verifier.ComputeDirectoryLeafKey(
                network, did.CanonicalBytes.Span);
            var revokedHash = AccountDirectoryAdc1Verifier.ComputeRevokedDcaAuthorizationIdsHash(revoked);
            var adcSigningInput = AccountDirectoryAdc1Codec.CreateDeviceIssuerSigningInput(
                network, directoryLeaf, 1, 0, new byte[32],
                Ref("DPA1", accountCertificate.CanonicalHash.Span),
                Ref("DRS1", revocationSnapshot.CanonicalHash.Span),
                dmd.RecordHash.Span, dab.RecordHash.Span, revokedHash,
                20, 1);
            var adc = new AccountDirectoryAdc1(
                network, directoryLeaf, 1, 0, new byte[32],
                Ref("DPA1", accountCertificate.CanonicalHash.Span),
                Ref("DRS1", revocationSnapshot.CanonicalHash.Span),
                dmd.RecordHash.Span, dab.RecordHash.Span, revokedHash,
                20, 1,
                PublicKeyAuth.SignDetached(adcSigningInput, deviceIssuerKey.PrivateKey));
            var checkpoint = AccountDirectoryAdc1Verifier.Verify(adc, Binding, Directory, revoked, 1);
            Adc = AccountDirectoryAdc1Codec.Encode(adc);

            var freshnessArtifacts = CreateFreshness(
                network, checkpoint, identity, trustedUnixSeconds, BootId, CurrentMonotonicSample);
            Freshness = freshnessArtifacts.Freshness;
            NetworkAuthority = freshnessArtifacts.Authority.Verified;
            NetworkWitnesses = freshnessArtifacts.Authority.Witnesses;
            Adh = freshnessArtifacts.Adh;
            Adp = freshnessArtifacts.Adp;
            var lookupPreimage = new byte[checked(network.Length + did.CanonicalBytes.Length)];
            network.CopyTo(lookupPreimage, 0);
            did.CanonicalBytes.Span.CopyTo(lookupPreimage.AsSpan(network.Length));
            var directoryLookupKey = AccountDirectoryCrypto.Sha256Domain(
                AccountDirectoryAdc1Verifier.LookupDomain, lookupPreimage);
            var adl = AccountDirectoryAdl1Codec.Encode(new AccountDirectoryAdl1(
                network, directoryLookupKey, Freshness.AdhGeneration,
                Freshness.ExactAdh1CoreHash.Span, 1, new byte[38], new byte[32]));
            Assert.Equal(network, accountCertificate.NetworkId.ToArray());
            Assert.Equal(network, dmd.NetworkId.ToArray());
            Assert.Equal(accountHash, dmd.DeepAccountId.ToArray());
            Assert.Equal(dpaRef.CanonicalBytes.ToArray(), dmd.Dpa1Reference.CanonicalBytes.ToArray());
            Assert.Equal(network, dca.NetworkId.ToArray());
            Assert.Equal(accountHash, dca.DeepAccountId.ToArray());
            Assert.Equal(dpaRef.CanonicalBytes.ToArray(), dca.Dpa1Reference.CanonicalBytes.ToArray());
            Assert.Equal(dmd.DirectoryGeneration, dca.AuthorizedDmd1Generation);
            Assert.Equal(dmd.RecordHash.ToArray(), dca.AuthorizedDmd1Hash.ToArray());
            Assert.Equal(deviceId, dca.PublisherDeviceId.ToArray());
            Assert.Equal(accountHash, dab.DeepAccountId.ToArray());
            Assert.Equal(dpaRef.CanonicalBytes.ToArray(), dab.Dpa1Reference.CanonicalBytes.ToArray());
            var bundleFields = new ReadOnlyMemory<byte>[] { network,accountHash,accountCertificate.CanonicalBytes,Ref("DRS1",revocationSnapshot.CanonicalHash.Span),dmd.CanonicalBytes,dca.CanonicalBytes,Bytes(32,0x54),U64(0),new byte[32],deviceCertificate.DeviceId,new byte[]{1},xpsList,new byte[]{1},descriptor,Array.Empty<byte>(),U32(1),U64(20),U64(90),Bytes(64,0x55),adl,Join(U64(Freshness.AdhGeneration),Freshness.ExactAdh1CoreHash.ToArray()),did.RecordHash,did.AddressPublicKey,dab.CanonicalBytes };
            Bundle = SignBundle(bundleFields);
            Dcr = DcrFor(Bundle);
        }

        internal VerifiedContactBundleClosure Promote(
            ContactRecord dcr,
            byte[]? bootId = null,
            ulong? currentMonotonicSample = null) =>
            ContactCodec.VerifyDcr1Closure(
                dcr, Authorization, Freshness, bootId ?? BootId,
                currentMonotonicSample ?? CurrentMonotonicSample);
        internal VerifiedContactBundleClosure PromoteWithFreshness(
            ContactRecord dcr,
            VerifiedAccountDirectoryFreshness freshness) =>
            ContactCodec.VerifyDcr1Closure(
                dcr, Authorization, freshness, BootId, CurrentMonotonicSample);
        internal ReadOnlyMemory<byte>[] BundleFields() => Enumerable.Range(1, 24).Select(Bundle.Field).ToArray();
        internal ContactRecord SignBundle(IReadOnlyList<ReadOnlyMemory<byte>> input) => DeviceRecord("DCB1", input, 19);
        internal ContactRecord DcrFor(ContactRecord bundle)
        {
            var support = new byte[6 + drs.Length + 6 + dpd.Length]; BinaryPrimitives.WriteUInt16BigEndian(support, 1); BinaryPrimitives.WriteUInt32BigEndian(support.AsSpan(2), checked((uint)drs.Length)); drs.CopyTo(support, 6);
            var offset = 6 + drs.Length; BinaryPrimitives.WriteUInt16BigEndian(support.AsSpan(offset), 2); BinaryPrimitives.WriteUInt32BigEndian(support.AsSpan(offset + 2), checked((uint)dpd.Length)); dpd.CopyTo(support, offset + 6);
            return DcrFor(bundle, 2, support);
        }

        internal ContactRecord DcrFor(ContactRecord bundle, ushort count, byte[] support) =>
            ContactCodecValidation.AuthorRecord("DCR1", [bundle.Field(1), bundle.CanonicalBytes, U16(count), support]);

        internal (byte[] Drs, byte[] Dpd) SupportObjects() => (drs.ToArray(), dpd.ToArray());

        internal ContactRecord DcrWithXirExpiry(ulong expiresAt)
        {
            var fields = BundleFields();
            var descriptor = fields[13].ToArray();
            var xir = ContactCodec.Decode("XIR1", descriptor.AsSpan(40, 611));
            var xirFields = Enumerable.Range(1, 18).Select(xir.Field).ToArray();
            xirFields[13] = U64(expiresAt);
            var changedXir = DeviceRecord("XIR1", xirFields, 17);
            SHA256.HashData(changedXir.CanonicalBytes.Span).CopyTo(descriptor, 4);
            changedXir.CanonicalBytes.Span.CopyTo(descriptor.AsSpan(40));
            fields[13] = descriptor;
            return DcrFor(SignBundle(fields));
        }

        internal ContactRecord DcrWithUnverifiedDpd()
        {
            var alternateDpdBytes = dpd.ToArray();
            alternateDpdBytes[FieldOffset(alternateDpdBytes, 7)] ^= 1;
            var alternateDpd = IdentityCodec.DecodeDeviceCertificate(alternateDpdBytes);
            var alternateDpdReference = ApplicationCoreCodec.CreateArtifactReference((ushort)ArtifactType.Dpd1,
                checked((uint)alternateDpd.CanonicalBytes.Length), alternateDpd.CanonicalHash.Span);

            var currentDmd = ApplicationCoreCodec.DecodeDmd1(Bundle.Field(5).Span);
            var alternateDmd = ApplicationCoreCodec.AuthorDmd1(currentDmd.NetworkId.Span,
                currentDmd.DeepAccountId.Span, currentDmd.AccountGeneration, currentDmd.Dpa1Reference,
                currentDmd.Drs1Reference, currentDmd.DirectoryGeneration, currentDmd.PredecessorDmd1Hash.Span,
                [new DeviceDirectoryEntry(currentDmd.ActiveDevices[0].DeviceId.Span, alternateDpdReference)],
                currentDmd.IssuedAtUnixSeconds, currentDmd.DeviceIssuerSignature.Span);

            var currentDca = ApplicationCoreCodec.DecodeDca1(Bundle.Field(6).Span);
            var alternateDca = ApplicationCoreCodec.AuthorDca1(currentDca.NetworkId.Span,
                currentDca.DeepAccountId.Span, currentDca.Dpa1Reference, alternateDmd.DirectoryGeneration,
                alternateDmd.RecordHash.Span, currentDca.AuthorizationId.Span, currentDca.PublisherDeviceId.Span,
                currentDca.AllowedInviteKindMask, currentDca.MaximumBundleGeneration,
                currentDca.NotBeforeUnixSeconds, currentDca.ExpiresAtUnixSeconds,
                currentDca.AccountSignature.Span, currentDca.ExactDid1Hash.Span, currentDca.Dab1Reference);

            var fields = BundleFields();
            fields[4] = alternateDmd.CanonicalBytes;
            fields[5] = alternateDca.CanonicalBytes;
            var xpsList = fields[11].ToArray();
            var xps = xpsList.AsSpan(5, 352).ToArray();
            Ref("DPD1", alternateDpd.CanonicalHash.Span).CopyTo(xps, FieldOffset(xps, 4));
            PublicKeyAuth.SignDetached(ContactCodec.SignatureInput(
                "Deep/ContactResolver/V1/prekey-service", ProjectRaw(xps, 11)), Device.PrivateKey)
                .CopyTo(xps, FieldOffset(xps, 12));
            xps.CopyTo(xpsList, 5);
            fields[11] = xpsList;
            return DcrFor(SignBundle(fields), 2, Support((1, drs), (2, alternateDpdBytes)));
        }

        private static FreshnessArtifacts CreateFreshness(
            byte[] network,
            VerifiedAccountDirectoryCheckpoint checkpoint,
            VerifiedApplicationIdentityClosure identity,
            ulong observedUnixSeconds,
            byte[] bootId,
            ulong currentMonotonicSample)
        {
            var authority = CreateAuthority(network);
            var emptyAppendRoot = AccountDirectoryRfc6962.ComputeEmptyTreeHash();
            var emptyMapRoot = AccountDirectorySparseMap.EmptyMapRoot.ToArray();
            var previousHead = CreateHead(
                authority, 0, new byte[32], 0, emptyAppendRoot, emptyMapRoot);
            var lkg = new AccountDirectoryProtectedLkg(AccountDirectoryAdh1Codec.Encode(previousHead));

            var query = checkpoint.Checkpoint.DirectoryLeafKey.ToArray();
            var adcReference = Ref(
                "ADC1", AccountDirectoryCrypto.ComputeAdc1ArtifactHash(checkpoint.Checkpoint));
            var bitmap = new byte[32];
            var mapRoot = AccountDirectorySparseMap.ComputePresentRoot(
                query, adcReference, bitmap, []);
            var transition = Join(
                U16(1), U64(0), query, new byte[38], adcReference,
                emptyMapRoot, mapRoot);
            var commitment = AccountDirectoryCrypto.Sha256Domain(
                "Deep/AccountDirectory/V1/transition", transition);
            var appendRoot = AccountDirectoryRfc6962.ComputeLeafHash(commitment);
            var head = CreateHead(
                authority, 1, lkg.CoreHash.ToArray(), 1, appendRoot, mapRoot);
            var headBytes = AccountDirectoryAdh1Codec.Encode(head);

            var nonce = Bytes(32, 0x31);
            var dtt = CreateDtt(authority, head, nonce, observedUnixSeconds);
            var dttBytes = AccountDirectoryDtt1Codec.Encode(dtt);
            var dttHash = AccountDirectoryCrypto.ComputeDtt1CoreHash(dtt);
            var activeDevices = identity.ActiveDevices
                .OrderBy(static device => device.Certificate.DeviceId.ToArray(), ByteArrayComparer.Instance)
                .Select(static device => Join(
                    U32(checked((uint)device.Certificate.CanonicalBytes.Length)),
                    device.Certificate.CanonicalBytes.ToArray()))
                .ToArray();
            var adcBytes = AccountDirectoryAdc1Codec.Encode(checkpoint.Checkpoint);
            var adpBytes = Write("ADP1",
            [
                network, new byte[] { 1 }, query, headBytes,
                U64(0), lkg.CoreHash.ToArray(), new byte[] { 0 }, Array.Empty<byte>(),
                bitmap, U16(0), Array.Empty<byte>(), new byte[] { 1 },
                new byte[] { 0 }, Array.Empty<byte>(), dttHash,
                adcBytes, checkpoint.Binding.DeepId.RecordHash,
                checkpoint.Binding.DeepId.AddressPublicKey,
                checkpoint.Binding.Record.CanonicalBytes,
                identity.Account.Certificate.CanonicalBytes,
                identity.Revocations.Snapshot.CanonicalBytes,
                checkpoint.Directory.Record.CanonicalBytes,
                new byte[] { checked((byte)activeDevices.Length) }, Join(activeDevices),
                transition, U64(0), new byte[] { 0 }, Array.Empty<byte>(),
            ]);
            var window = new AccountDirectoryMonotonicRequestWindow(
                bootId, 1_000, 1_002, currentMonotonicSample);
            var freshness = AccountDirectoryCurrentProofVerifier.Verify(
                authority.Verified, headBytes, dttBytes, adpBytes,
                nonce, query, window, lkg, checkpoint, supportedReader: 1);
            return new FreshnessArtifacts(freshness, headBytes, adpBytes, authority);
        }

        private static AuthorityFixture CreateAuthority(byte[] network)
        {
            var root = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x20));
            var witnesses = Enumerable.Range(0, 3).Select(index => new Witness(
                Bytes(32, checked((byte)(0x40 + index))),
                PublicKeyAuth.GenerateKeyPair(Bytes(32, checked((byte)(0x50 + index)))),
                Bytes(32, checked((byte)(0x60 + index))))).ToArray();
            var dtsBytes = CreateDts(network, root);
            var dts = AccountDirectoryDts1Codec.Decode(dtsBytes);
            var policyHash = AccountDirectoryCrypto.ComputeDts1PolicyHash(dts);
            var xnaBytes = CreateXna(network, root, witnesses, policyHash);
            var xna = XPointNetworkCodec.Parse<Xna1Record>(xnaBytes);
            var verified = XPointNetworkAuthorityVerifier.Verify(
                new XPointNetworkGenesisPin(network, xna.CoreHash.Span),
                [xnaBytes], [dtsBytes]);
            return new AuthorityFixture(verified, witnesses);
        }

        private static AccountDirectoryAdh1 CreateHead(
            AuthorityFixture authority,
            ulong generation,
            byte[] predecessor,
            ulong treeSize,
            byte[] appendRoot,
            byte[] mapRoot)
        {
            var selected = authority.Witnesses.Take(2)
                .OrderBy(static witness => witness.Id, ByteArrayComparer.Instance).ToArray();
            var placeholders = selected.Select((witness, index) =>
                new AccountDirectoryAdh1WitnessEntry(
                    witness.Id, Bytes(64, checked((byte)(0x70 + index))))).ToArray();
            var unsigned = new AccountDirectoryAdh1(
                authority.Verified.NetworkId.Span, generation, predecessor, treeSize,
                appendRoot, mapRoot, authority.Verified.AuthorityCoreReference.Span,
                authority.Verified.DirectoryWitnessPolicyHash.Span,
                20, 80, 1, placeholders);
            var signingInput = AccountDirectoryCrypto.ComputeAdh1SigningInput(unsigned);
            var receipts = selected.Select(witness => new AccountDirectoryAdh1WitnessEntry(
                witness.Id, PublicKeyAuth.SignDetached(signingInput, witness.Key.PrivateKey))).ToArray();
            return new AccountDirectoryAdh1(
                unsigned.NetworkId.Span, unsigned.LogGeneration,
                unsigned.PredecessorAdh1CoreHash.Span, unsigned.TreeSize,
                unsigned.AppendLogMerkleRoot.Span, unsigned.CurrentValueMapRoot.Span,
                unsigned.ExactXnaAuthorityCoreReference.Span, unsigned.WitnessPolicyHash.Span,
                unsigned.ValidFrom, unsigned.ValidUntil, unsigned.MinimumReader, receipts);
        }

        private static AccountDirectoryDtt1 CreateDtt(
            AuthorityFixture authority,
            AccountDirectoryAdh1 head,
            byte[] nonce,
            ulong observedUnixSeconds)
        {
            var selected = authority.Witnesses.Take(2)
                .OrderBy(static witness => witness.Id, ByteArrayComparer.Instance).ToArray();
            var placeholders = selected.Select((witness, index) =>
                new AccountDirectoryDtt1WitnessReceipt(
                    witness.Id, Bytes(64, checked((byte)(0x80 + index))))).ToArray();
            var headHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(head);
            var issuanceEpoch = AccountDirectoryDtt1IssuanceEpoch.Derive(
                authority.Verified, observedUnixSeconds, 1);
            var unsigned = new AccountDirectoryDtt1(
                authority.Verified.NetworkId.Span, nonce, observedUnixSeconds, 1,
                headHash, head.LogGeneration, Bytes(32, 0x90), 1,
                authority.Verified.AuthorityCoreReference.Span,
                authority.Verified.DirectoryWitnessPolicyHash.Span,
                observedUnixSeconds, checked(observedUnixSeconds + 60),
                issuanceEpoch.Id.Span, placeholders);
            var signingInput = AccountDirectoryCrypto.ComputeDtt1SigningInput(unsigned);
            var receipts = selected.Select(witness => new AccountDirectoryDtt1WitnessReceipt(
                witness.Id, PublicKeyAuth.SignDetached(signingInput, witness.Key.PrivateKey))).ToArray();
            return new AccountDirectoryDtt1(
                unsigned.NetworkId.Span, unsigned.ClientNonce.Span,
                unsigned.ObservedUnixTime, unsigned.UncertaintySeconds,
                unsigned.CurrentAdh1CoreHash.Span, unsigned.CurrentAdh1Generation,
                unsigned.CurrentXnv1CoreHash.Span, unsigned.CurrentXnv1Generation,
                unsigned.AuthorizingXna1CoreReference.Span, unsigned.WitnessPolicyHash.Span,
                unsigned.IssuedAt, unsigned.ExpiresAt, unsigned.IssuanceEpochId.Span, receipts);
        }

        private static byte[] CreateDts(byte[] network, KeyPair root)
        {
            var sources = new[]
            {
                new AccountDirectoryDts1Source(
                    Bytes(32, 0x10), Bytes(32, 0x12), 1,
                    "time-a.example", 443, Bytes(32, 0x14), 1),
                new AccountDirectoryDts1Source(
                    Bytes(32, 0x11), Bytes(32, 0x13), 1,
                    "time-b.example", 443, Bytes(32, 0x15), 1),
            };
            var rootId = Bytes(32, 0x20);
            var placeholder = new[]
            {
                new AccountDirectoryDts1RootReceipt(rootId, Bytes(64, 0x21)),
            };
            var unsigned = new AccountDirectoryDts1(
                network, 0, new byte[32], sources, 2, 2, 30, 1,
                1, 1_000, 1, 0, placeholder);
            var signature = PublicKeyAuth.SignDetached(
                AccountDirectoryCrypto.ComputeDts1SigningInput(unsigned), root.PrivateKey);
            return AccountDirectoryDts1Codec.Encode(new AccountDirectoryDts1(
                network, 0, new byte[32], sources, 2, 2, 30, 1,
                1, 1_000, 1, 0,
                [new AccountDirectoryDts1RootReceipt(rootId, signature)]));
        }

        private static byte[] CreateXna(
            byte[] network,
            KeyPair root,
            Witness[] witnesses,
            byte[] policyHash)
        {
            ReadOnlyMemory<byte>[] fields = new ReadOnlyMemory<byte>[20];
            fields[0] = network; fields[1] = U64(0); fields[2] = new byte[32];
            fields[3] = new byte[] { 1 };
            fields[4] = Join(Bytes(32, 0x20), U64(0), root.PublicKey);
            fields[5] = new byte[] { 1 }; fields[6] = U64(0); fields[7] = U16(1);
            fields[8] = new byte[] { 3 };
            fields[9] = Join(witnesses.Select(witness => Join(
                witness.Id, U64(0), witness.Key.PublicKey, witness.FailureDomain)).ToArray());
            fields[10] = new byte[] { 2 }; fields[11] = Ref("DTS1", policyHash);
            fields[12] = policyHash; fields[13] = U32(30); fields[14] = U64(1);
            fields[15] = U64(1); fields[16] = U64(1); fields[17] = U64(1_000);
            fields[18] = new byte[] { 1 };
            fields[19] = Join(Bytes(32, 0x20), Bytes(64, 0x22));
            var unsigned = XPointNetworkCodec.Parse<Xna1Record>(
                XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields));
            fields[19] = Join(
                Bytes(32, 0x20),
                PublicKeyAuth.SignDetached(
                    XPointNetworkCrypto.ComputeSigningInput(unsigned), root.PrivateKey));
            return XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields);
        }

        internal sealed record Witness(byte[] Id, KeyPair Key, byte[] FailureDomain);
        internal sealed record AuthorityFixture(
            VerifiedXPointNetworkAuthority Verified,
            Witness[] Witnesses);
        private sealed record FreshnessArtifacts(
            VerifiedAccountDirectoryFreshness Freshness,
            byte[] Adh,
            byte[] Adp,
            AuthorityFixture Authority);

        private ContactRecord DeviceRecord(string magic, IReadOnlyList<ReadOnlyMemory<byte>> input, int signatureTag)
        {
            var fields = input.ToArray(); var provisional = ContactCodecValidation.AuthorRecord(magic, fields);
            fields[signatureTag - 1] = PublicKeyAuth.SignDetached(provisional.SignatureInput.ToArray(), Device.PrivateKey);
            return ContactCodecValidation.AuthorRecord(magic, fields);
        }
        private static byte[] Write(string magic, IReadOnlyList<ReadOnlyMemory<byte>> fields)
        {
            var bytes = new byte[12 + fields.Sum(field => 8 + field.Length)]; Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0x0201); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), checked((ushort)fields.Count)); var offset = 12;
            for (var index = 0; index < fields.Count; index++) { BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(offset), checked((ushort)(index + 1))); BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset + 4), checked((uint)fields[index].Length)); offset += 8; fields[index].Span.CopyTo(bytes.AsSpan(offset)); offset += fields[index].Length; } return bytes;
        }
        private static byte[] Join(params byte[][] parts) { var output = new byte[parts.Sum(part => part.Length)]; var offset = 0; foreach (var part in parts) { part.CopyTo(output, offset); offset += part.Length; } return output; }
        private static ApplicationArtifactReference AppRef(CanonicalIdentityArtifact artifact) =>
            ApplicationCoreCodec.CreateArtifactReference((ushort)artifact.ArtifactType,
                checked((uint)artifact.CanonicalBytes.Length), artifact.CanonicalHash.Span);
        private static ReadOnlyMemory<byte>[] MinimumFields(RecordDefinition definition) =>
            definition.Fields.Select(field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();
        private sealed class ByteArrayComparer : IComparer<byte[]>
        {
            internal static readonly ByteArrayComparer Instance = new();
            public int Compare(byte[]? x, byte[]? y) => (x ?? []).AsSpan().SequenceCompareTo(y ?? []);
        }
    }

    private sealed class CryptoRouteFixture
    {
        private readonly (byte[] Id, KeyPair Key)[] witnesses;
        private CryptoRouteFixture((byte[] Id, KeyPair Key)[] witnesses, KeyPair device) { this.witnesses = witnesses; Device = device; }

        internal KeyPair Device { get; }
        internal ContactRecord Xir { get; private set; } = null!;
        internal ContactRecord Xrr { get; private set; } = null!;
        internal ContactRecord Xra { get; private set; } = null!;
        internal ContactRecord Xrc { get; private set; } = null!;
        internal ContactRecord Xss { get; private set; } = null!;
        internal ContactRecord Pmt { get; private set; } = null!;
        internal ContactRecord Pms { get; private set; } = null!;
        internal VerifiedContactNetworkAuthority Authority { get; private set; } = null!;

        internal static CryptoRouteFixture Create()
        {
            var authority = ContactNetworkAuthorityVerifierTests.Fixture.Create();
            var witnesses = authority.Witnesses.Take(2)
                .Select(static witness => (witness.Id, witness.Key)).ToArray();
            var fixture = new CryptoRouteFixture(witnesses, authority.Identity.Device);
            fixture.Build(authority);
            return fixture;
        }

        private void Build(ContactNetworkAuthorityVerifierTests.Fixture verified)
        {
            Authority = verified.VerifyAsync().AsTask().GetAwaiter().GetResult();
            var network = verified.Network;
            var xnv = Authority.Xnv1CoreReference.ToArray();
            var xnh = Authority.Xnh1CoreReference.ToArray();
            var adh = Authority.Adh1CoreReference.ToArray();
            var dpd = Authority.RecipientDpd1Reference.ToArray();
            var dca = Authority.Dca1Reference.ToArray();
            Pmt = verified.Pmt;
            Pms = verified.Pms;
            Xra = DeviceRecord("XRA1", [network,Bytes(32,8),U64(0),new byte[32],ContactCodec.ArtifactReference("PMT2",Pmt).CanonicalBytes,Pms.Field(3),U16(1),U32(10),Bytes(32,10),Bytes(32,11),Bytes(32,12),U64(20),U64(90),Authority.RecipientDeviceId,dpd,Bytes(64,14)], 16);

            var ranked = Pms.Field(6).ToArray();

            var replicaEntries = new byte[128];
            for (var index = 0; index < 2; index++) { ranked.AsSpan(index * 32, 32).CopyTo(replicaEntries.AsSpan(index * 64)); Bytes(32, (byte)(0xd0 + index)).CopyTo(replicaEntries, index * 64 + 32); }
            Xrc = WitnessRecord("XRC1", [network,Bytes(32,15),U64(0),new byte[32],ContactCodec.ArtifactReference("XRA1",Xra).CanonicalBytes,ContactCodec.ArtifactReference("PMT2",Pmt).CanonicalBytes,Pms.ArtifactHash,xnv,xnh,Bytes(32,16),Xra.Field(10),Xra.Field(11),U64(1),new byte[]{2},replicaEntries,U64(20),U64(20),U64(80),adh,new byte[]{2},DummyReceipts()], 21);
            Xss = WitnessRecord("XSS1", [network,Xrc.Field(2),U64(1),Xrc.CoreHash,ContactCodec.ArtifactReference("XRC1",Xrc).CanonicalBytes,ContactCodec.ArtifactReference("XRC1",Xrc).CanonicalBytes,ContactCodec.ArtifactReference("PMT2",Pmt).CanonicalBytes,xnv,Pms.ArtifactHash,U64(20),U64(80),adh,new byte[]{2},DummyReceipts()], 14);
            Xrr = DeviceRecord("XRR1", [network,Bytes(32,17),U64(0),new byte[32],ContactCodec.ArtifactReference("XRA1",Xra).CanonicalBytes,ContactCodec.ArtifactReference("XRC1",Xrc).CanonicalBytes,ContactCodec.ArtifactReference("XSS1",Xss).CanonicalBytes,ContactCodec.ArtifactReference("PMT2",Pmt).CanonicalBytes,Pms.ArtifactHash,Bytes(32,18),Xra.Field(9),new byte[]{1},U32(1),U16(1),U64(20),U64(20),U64(80),dpd,Bytes(64,19),new byte[2]], 19);
            Xir = DeviceRecord("XIR1", [network,Bytes(32,20),U64(0),new byte[32],ContactCodec.ArtifactReference("PMT2",Pmt).CanonicalBytes,Xra.Field(6),Xra.Field(10),Xra.Field(11),new byte[]{1},U32(0),U16(2),Xra.Field(9),U64(20),U64(90),dpd,dca,Bytes(64,21),ContactCodec.ArtifactReference("XRA1",Xra).CanonicalBytes], 17);

        }

        internal ContactRecord ResignDevice(ContactRecord source, int changedTag, byte[] value, int signatureTag)
        {
            var fields = Enumerable.Range(1, FieldCount(source)).Select(source.Field).ToArray();
            fields[changedTag - 1] = value;
            return DeviceRecord(source.Magic, fields, signatureTag);
        }

        internal ContactRecord ResignWitness(ContactRecord source, int changedTag, byte[] value, int receiptTag)
        {
            var fields = Enumerable.Range(1, FieldCount(source)).Select(source.Field).ToArray();
            fields[changedTag - 1] = value;
            return WitnessRecord(source.Magic, fields, receiptTag);
        }

        internal ContactRecord ReversePmsSelection()
        {
            var fields = Enumerable.Range(1, 11).Select(Pms.Field).ToArray();
            var ranked = fields[5].ToArray();
            ranked.AsSpan(0, 32).CopyTo(ranked.AsSpan(32, 32));
            Pms.Field(6).Span.Slice(32, 32).CopyTo(ranked.AsSpan(0, 32));
            fields[5] = ranked;
            fields[6] = SelectionHash(fields);
            return WitnessRecord("PMS2", fields, 11);
        }

        internal void AssertIndependentWitnessSignatures(ContactRecord record)
        {
            var tag = record.Magic switch { "PMT2" => 16, "PMS2" => 11, "XRC1" => 21, "XSS1" => 14, _ => throw new InvalidOperationException() };
            var receipts = record.Field(tag).Span;
            for (var index = 0; index < witnesses.Length; index++)
                Assert.True(PublicKeyAuth.VerifyDetached(receipts.Slice(index * 96 + 32, 64).ToArray(), record.SignatureInput.ToArray(), witnesses[index].Key.PublicKey));
        }

        private ContactRecord DeviceRecord(string magic, IReadOnlyList<ReadOnlyMemory<byte>> input, int signatureTag)
        {
            var fields = input.ToArray();
            var provisional = ContactCodecValidation.AuthorRecord(magic, fields);
            fields[signatureTag - 1] = PublicKeyAuth.SignDetached(provisional.SignatureInput.ToArray(), Device.PrivateKey);
            return ContactCodecValidation.AuthorRecord(magic, fields);
        }

        private ContactRecord WitnessRecord(string magic, IReadOnlyList<ReadOnlyMemory<byte>> input, int receiptTag)
        {
            var fields = input.ToArray();
            var provisional = ContactCodecValidation.AuthorRecord(magic, fields);
            var receipts = new byte[96 * witnesses.Length];
            for (var index = 0; index < witnesses.Length; index++)
            {
                witnesses[index].Id.CopyTo(receipts, index * 96);
                PublicKeyAuth.SignDetached(provisional.SignatureInput.ToArray(), witnesses[index].Key.PrivateKey).CopyTo(receipts, index * 96 + 32);
            }
            fields[receiptTag - 1] = receipts;
            return ContactCodecValidation.AuthorRecord(magic, fields);
        }

        private byte[] DummyReceipts()
        {
            var receipts = new byte[96 * witnesses.Length];
            for (var index = 0; index < witnesses.Length; index++) { witnesses[index].Id.CopyTo(receipts, index * 96); Bytes(64, (byte)(0x90 + index)).CopyTo(receipts, index * 96 + 32); }
            return receipts;
        }

        private static int FieldCount(ContactRecord record) => record.Magic switch { "XIR1" => 18, "XRA1" => 16, "XRR1" => 20, "XRC1" => 21, "XSS1" => 14, "PMT2" => 16, "PMS2" => 11, _ => throw new InvalidOperationException() };
        private static byte[] Rows(int width, int count, byte seed) { var bytes = new byte[width * count]; for (var index = 0; index < count; index++) Bytes(32, (byte)(seed + index * 0x20)).CopyTo(bytes, index * width); return bytes; }

        private static byte[] RankedNodes(ContactRecord pmt, ReadOnlySpan<byte> placement)
        {
            var domain = Encoding.ASCII.GetBytes("Deep/XPoint/V1/PMS2/rendezvous-sha256/v2");
            var pmtRef = ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes.ToArray();
            var placementBytes = placement.ToArray();
            return pmt.Field(9).ToArray().Chunk(136).Select(row => row[..32]).Select(node =>
            {
                var input = Join(domain, new byte[]{0}, pmt.Field(1).ToArray(), pmtRef, pmt.Field(6).ToArray(), placementBytes, node);
                return (Node: node, Score: SHA256.HashData(input));
            }).OrderBy(item => item.Score, ByteArrayComparer.Instance).ThenBy(item => item.Node, ByteArrayComparer.Instance).SelectMany(item => item.Node).ToArray();
        }

        private static byte[] SelectionHash(IReadOnlyList<ReadOnlyMemory<byte>> fields)
        {
            var projection = Write("PMS2", fields.Take(6).ToArray());
            var domain = Encoding.ASCII.GetBytes("Deep/XPoint/V1/PMS2/selection");
            var input = new byte[domain.Length + 5 + projection.Length]; domain.CopyTo(input, 0);
            BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(domain.Length + 1), checked((uint)projection.Length));
            projection.CopyTo(input, domain.Length + 5); return SHA256.HashData(input);
        }

        private static byte[] Write(string magic, IReadOnlyList<ReadOnlyMemory<byte>> fields)
        {
            var bytes = new byte[12 + fields.Sum(field => 8 + field.Length)]; Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0x0201);
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), checked((ushort)fields.Count)); var offset = 12;
            for (var index = 0; index < fields.Count; index++) { BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(offset), checked((ushort)(index + 1))); BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset + 4), checked((uint)fields[index].Length)); offset += 8; fields[index].Span.CopyTo(bytes.AsSpan(offset)); offset += fields[index].Length; }
            return bytes;
        }

        private static byte[] Join(params byte[][] parts) { var output = new byte[parts.Sum(part => part.Length)]; var offset = 0; foreach (var part in parts) { part.CopyTo(output, offset); offset += part.Length; } return output; }
        private sealed class ByteArrayComparer : IComparer<byte[]> { internal static readonly ByteArrayComparer Instance = new(); public int Compare(byte[]? left, byte[]? right) => left is null ? (right is null ? 0 : -1) : right is null ? 1 : left.AsSpan().SequenceCompareTo(right); }
    }
}
