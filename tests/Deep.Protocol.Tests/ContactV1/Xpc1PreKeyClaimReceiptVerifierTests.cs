using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.ContactV1;

public sealed class Xpc1PreKeyClaimReceiptVerifierTests
{
    [Fact]
    public async Task ClaimedReceiptMintsDefensiveCapability()
    {
        var fixture = await Fixture.CreateAsync();
        var verified = await fixture.VerifyAsync();

        Assert.Equal(Xpc1Status.Claimed, verified.Status);
        Assert.Equal(fixture.Request.RequestHash.ToArray(), verified.RequestHash.ToArray());
        Assert.Equal(fixture.Result.Field(18).ToArray(), verified.ClaimReceiptHash.ToArray());
        Assert.Equal(Xpi1Codec.ComputeHash(fixture.Result.Field(26).Span), verified.Xpi1Hash.ToArray());
        Assert.Equal(1UL, verified.InventoryEpoch);
        Assert.Equal((ushort)0, verified.InventoryIndex);
        Assert.Equal(fixture.Dpk2.OneTimeX25519PrekeyId.ToArray(), verified.SelectedOneTimePrekeyId.ToArray());
        Assert.Equal(2, verified.ReplicaNodeIds.Count);
        Assert.Equal(Dpk2Codec.Encode(fixture.Dpk2), verified.Offering.ExactBytes.ToArray());
        Assert.Equal(
            fixture.Dpk2.SignedX25519PrekeyPublic.ToArray(),
            verified.Offering.InitiatorAgreementPeerPublicKey.ToArray());

        var network = verified.NetworkId.ToArray();
        network[0] ^= 0xff;
        Assert.NotEqual(network, verified.NetworkId.ToArray());
    }

    [Fact]
    public async Task VerifiedBundleProjectsOnlyTheNetworkAuthorizedPreKeyService()
    {
        var fixture = await Fixture.CreateAsync();

        var service = fixture.Bundle.GetAuthorizedPreKeyService(fixture.Authority);

        Assert.Equal(fixture.Bundle.Bundle.ArtifactHash.ToArray(),
            service.Dcb1Hash.ToArray());
        Assert.Equal(fixture.Xps1.CanonicalBytes, service.ExactXps1.ToArray());
        Assert.Equal(SHA256.HashData(fixture.Xps1.CanonicalBytes),
            service.Xps1Hash.ToArray());
        Assert.Equal(fixture.Xps1.ServiceCapability,
            service.ServiceCapability.ToArray());
        Assert.Equal(fixture.Authority.RecipientDeviceId.ToArray(),
            service.DeviceId.ToArray());
        Assert.Empty(typeof(VerifiedContactPreKeyServiceClosure).GetConstructors());

        var copy = service.ServiceCapability.ToArray();
        copy[0] ^= 0xff;
        Assert.NotEqual(copy, service.ServiceCapability.ToArray());
    }

    [Fact]
    public async Task PublicSurfaceHasOneCapabilityProducerAndNoRawTrustInputs()
    {
        var method = Assert.Single(typeof(Xpc1PreKeyClaimReceiptVerifier)
            .GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly));
        Assert.Equal("VerifyAsync", method.Name);
        Assert.Equal(
            [typeof(Xpk1Request), typeof(Xpc1Result), typeof(VerifiedContactServicePlacement),
             typeof(VerifiedContactNetworkAuthority), typeof(VerifiedContactBundleClosure),
             typeof(OnionTrustedTimeAuthority), typeof(CancellationToken)],
            method.GetParameters().Select(static parameter => parameter.ParameterType).ToArray());
        Assert.Empty(typeof(VerifiedXpc1PreKeyClaimReceipt).GetConstructors());
        Assert.DoesNotContain(typeof(VerifiedXpc1PreKeyClaimReceipt).GetProperties(), property =>
            property.Name.Contains("Xpk1", StringComparison.OrdinalIgnoreCase) ||
            property.Name.Contains("Xpc1", StringComparison.OrdinalIgnoreCase) ||
            property.Name.Contains("PublicKey", StringComparison.OrdinalIgnoreCase) ||
            property.Name.Contains("Replay", StringComparison.OrdinalIgnoreCase));

        var fixture = await Fixture.CreateAsync();
        await AssertCodeAsync("NotDurablyClaimed", () => fixture.VerifyAsync(
            result: fixture.BuildUnclaimedResult()));
    }

    [Theory]
    [InlineData("dcb")]
    [InlineData("xps")]
    [InlineData("capability")]
    [InlineData("device")]
    public async Task RequestBindingSubstitutionRejects(string field)
    {
        var fixture = await Fixture.CreateAsync();
        var request = fixture.BuildRequest(
            serviceCapability: field == "capability" ? Bytes(32, 0xe1) : null,
            dcb1Hash: field == "dcb" ? Bytes(32, 0xe2) : null,
            xps1Hash: field == "xps" ? Bytes(32, 0xe3) : null,
            responderDeviceId: field == "device" ? Bytes(32, 0xe4) : null);
        var result = fixture.BuildResult(request, fixture.Dpk2);

        await Assert.ThrowsAsync<Xpc1PreKeyClaimReceiptException>(() =>
            fixture.VerifyAsync(request: request, result: result).AsTask());
    }

    [Theory]
    [InlineData("network")]
    [InlineData("account")]
    [InlineData("device")]
    [InlineData("generation")]
    [InlineData("dpd")]
    [InlineData("agreement")]
    [InlineData("dmd")]
    [InlineData("service")]
    public async Task Dpk2RecipientBindingSubstitutionRejects(string field)
    {
        var fixture = await Fixture.CreateAsync();
        var dpk2 = fixture.BuildDpk2(new DpkOverrides(
            NetworkId: field == "network" ? Bytes(16, 0x81) : null,
            AccountId: field == "account" ? Bytes(32, 0x82) : null,
            DeviceId: field == "device" ? Bytes(32, 0x83) : null,
            DeviceGeneration: field == "generation" ? 2UL : null,
            Dpd1Reference: field == "dpd" ? Reference("DPD1", 0x84) : null,
            AgreementKey: field == "agreement" ? Bytes(32, 0x85) : null,
            Dmd1Hash: field == "dmd" ? Bytes(32, 0x86) : null,
            ServiceGeneration: field == "service" ? 2UL : null));
        var result = fixture.BuildResult(fixture.Request, dpk2);

        var expected = field is "account" or "generation" or "agreement"
            ? "Dpk2RecipientMismatch"
            : "Xpi1RecipientMismatch";
        await AssertCodeAsync(expected, () => fixture.VerifyAsync(result: result));
    }

    [Fact]
    public async Task ResultDirectoryCommitAndDpkSignatureSubstitutionRejects()
    {
        var fixture = await Fixture.CreateAsync();

        await AssertCodeAsync("Dpk2RecipientMismatch", () => fixture.VerifyAsync(
            result: fixture.BuildResult(fixture.Request, fixture.Dpk2, dmd1Hash: Bytes(32, 0x91))));
        await AssertCodeAsync("Dpk2RecipientMismatch", () => fixture.VerifyAsync(
            result: fixture.BuildResult(fixture.Request, fixture.Dpk2, drs1Reference: Reference("DRS1", 0x92))));
        await AssertCodeAsync("PrekeySelectionMismatch", () => fixture.VerifyAsync(
            result: fixture.BuildResult(fixture.Request, fixture.Dpk2, claimCommitGeneration: 0)));

        var fake = fixture.BuildDpk2(new DpkOverrides(FakeBundleSignature: true));
        await AssertCodeAsync("Dpk2SignatureInvalid", () => fixture.VerifyAsync(
            result: fixture.BuildResult(fixture.Request, fake)));

        await AssertCodeAsync("Xpi1VerificationFailed", () => fixture.VerifyAsync(
            result: fixture.BuildResult(fixture.Request, fixture.Dpk2, fakeManifestSignature: true)));
    }

    [Fact]
    public async Task WrongPlacementNetworkTimeReplicaAndFailureDomainReject()
    {
        var fixture = await Fixture.CreateAsync();
        var wrongPlacement = ContactServicePlacementFactory.Create(
            fixture.Core.CurrentNetwork, ContactServiceRequestKind.ClaimPreKey, Bytes(32, 0xa8));
        await AssertCodeAsync("PlacementMismatch", () => fixture.VerifyAsync(placement: wrongPlacement));

        var wrongNetworkRequest = fixture.BuildRequest(networkId: Bytes(16, 0xa9));
        await AssertCodeAsync("PlacementMismatch", () => fixture.VerifyAsync(
            request: wrongNetworkRequest,
            result: fixture.BuildResult(wrongNetworkRequest, fixture.Dpk2)));

        await AssertCodeAsync("TrustedTimeInvalid", () => fixture.VerifyAsync(
            clock: new FixedClock(new OnionMonotonicReading(fixture.Core.BootId, 1_050))));
        await AssertCodeAsync("ClaimTimeInvalid", () => fixture.VerifyAsync(
            result: fixture.BuildResult(fixture.Request, fixture.Dpk2, serverTime: 31)));
        await AssertCodeAsync("ReplicaSignatureInvalid", () => fixture.VerifyAsync(
            result: fixture.BuildResult(fixture.Request, fixture.Dpk2, fakeReplicaSignature: true)));

        var repeatedDomain = await Fixture.CreateAsync(repeatReplicaFailureDomain: true);
        await AssertCodeAsync("ReplicaDiversityInvalid", () => repeatedDomain.VerifyAsync());
    }

    [Fact]
    public async Task ExactReplayIsStableAndChangedReplayRejects()
    {
        var fixture = await Fixture.CreateAsync();
        var first = await fixture.VerifyAsync();
        var exact = await fixture.VerifyAsync();
        VerifiedXpc1PreKeyClaimReceipt.RequireExactReplay(first, exact);

        var replayResult = fixture.BuildResult(fixture.Request, fixture.Dpk2, status: Xpc1Status.Replay);
        var replay = await fixture.VerifyAsync(result: replayResult);
        var error = Assert.Throws<Xpc1PreKeyClaimReceiptException>(() =>
            VerifiedXpc1PreKeyClaimReceipt.RequireExactReplay(first, replay));
        Assert.Equal("ChangedClaimReplay", error.Code);
    }

    [Fact]
    public async Task InternalBridgeBindsVerifiedDph2SessionAndClaim()
    {
        var fixture = await Fixture.CreateAsync();
        var provisional = fixture.BuildDph2(Bytes(32, 0xb1));
        var senderCommitment = MessagingWireCryptographicInputs.ComputeSenderEphemeralCommitment(provisional);
        var request = fixture.BuildRequest(senderEphemeralCommitment: senderCommitment);
        var result = fixture.BuildResult(request, fixture.Dpk2);
        var claim = await fixture.VerifyAsync(request: request, result: result);
        var dph2 = fixture.BuildDph2(result.Field(18).ToArray(), request);
        var initiation = new VerifiedDph2Initiation(
            dph2,
            new VerifiedDpk2Offering(fixture.Dpk2,
                MessagingWireCryptographicInputs.ComputeExactDpk2Hash(fixture.Dpk2)),
            MessagingWireCryptographicInputs.ComputeDph2TranscriptHash(fixture.Dpk2, dph2),
            MessagingWireCryptographicInputs.ComputeDph2FullReplayHash(dph2),
            MessagingWireCryptographicInputs.ComputeDph2ClaimBinding(dph2),
            Bytes(32, 0xc4));

        var cryptoClaim = VerifiedPreKeyClaimCapability.CreateFromVerifiedXpc1(claim, initiation);
        var consumed = cryptoClaim.Consume();
        Assert.Equal(request.OperationId.ToArray(), consumed.ClaimId);
        Assert.Equal(dph2.SessionId.ToArray(), consumed.SessionId);
        Assert.Equal(fixture.Dpk2.OneTimeX25519PrekeyId.ToArray(), consumed.X25519PreKeyId);
        Assert.Equal(fixture.Dpk2.MlKemPrekeyId.ToArray(), consumed.MlKemPreKeyId);
        Assert.Equal(initiation.FullReplayHash.ToArray(), consumed.InitiationHash);
        var consumedAgain = Assert.Throws<MessagingCryptoException>(() => cryptoClaim.Consume());
        Assert.Equal(MessagingCryptoError.CapabilityConsumed, consumedAgain.Error);
        var bridgeAgain = Assert.Throws<Xpc1PreKeyClaimReceiptException>(() =>
            VerifiedPreKeyClaimCapability.CreateFromVerifiedXpc1(claim, initiation));
        Assert.Equal("ClaimCapabilityConsumed", bridgeAgain.Code);
    }

    [Fact]
    public async Task InitialSessionHandoffSeparatesDeviceAndProtocolLanes()
    {
        var fixture = await Fixture.CreateAsync();
        var provisional = fixture.BuildDph2(Bytes(32, 0xd1));
        var senderCommitment = MessagingWireCryptographicInputs.ComputeSenderEphemeralCommitment(provisional);
        var request = fixture.BuildRequest(senderEphemeralCommitment: senderCommitment);
        var result = fixture.BuildResult(request, fixture.Dpk2);
        var claim = await fixture.VerifyAsync(request: request, result: result);
        var dph2 = fixture.BuildDph2(result.Field(18).ToArray(), request);
        var initiation = new VerifiedDph2Initiation(
            dph2,
            new VerifiedDpk2Offering(fixture.Dpk2,
                MessagingWireCryptographicInputs.ComputeExactDpk2Hash(fixture.Dpk2)),
            MessagingWireCryptographicInputs.ComputeDph2TranscriptHash(fixture.Dpk2, dph2),
            MessagingWireCryptographicInputs.ComputeDph2FullReplayHash(dph2),
            MessagingWireCryptographicInputs.ComputeDph2ClaimBinding(dph2),
            Bytes(32, 0xc5));

        using var handoff = claim.BindForInitialSession(initiation);
        using var reservation = handoff.ConsumeForDevicePreKeyOwner();
        Assert.Equal(Dpk2PrekeyKind.OneTime, reservation.Kind);
        Assert.Equal((ushort)0, reservation.LastResortUseCounter);
        Assert.Equal(request.OperationId.ToArray(), reservation.OperationId.ToArray());
        Assert.Equal(dph2.SessionId.ToArray(), reservation.SessionId.ToArray());
        Assert.Equal(fixture.Dpk2.OneTimeX25519PrekeyId.ToArray(), reservation.X25519PreKeyId.ToArray());
        Assert.Equal(fixture.Dpk2.MlKemPrekeyId.ToArray(), reservation.MlKemPreKeyId.ToArray());
        Assert.Throws<InvalidOperationException>(() => handoff.ConsumeForDevicePreKeyOwner());

        var protocolClaim = VerifiedPreKeyClaimCapability.CreateFromVerifiedInitialSession(handoff);
        var protocol = protocolClaim.Consume();
        Assert.Equal(request.OperationId.ToArray(), protocol.ClaimId);
        Assert.Equal(dph2.SessionId.ToArray(), protocol.SessionId);
        Assert.Equal(fixture.Dpk2.OneTimeX25519PrekeyId.ToArray(), protocol.X25519PreKeyId);
        Assert.Throws<InvalidOperationException>(() =>
            VerifiedPreKeyClaimCapability.CreateFromVerifiedInitialSession(handoff));
    }

    [Fact]
    public void LastResortInitialSessionHandoffHasNoOneTimeX25519Identifier()
    {
        var dpk2 = Deep.Protocol.Tests.MessagingWire.MessagingWireFixtures.Dpk2(
            Dpk2PrekeyKind.LastResort);
        var dph2 = Deep.Protocol.Tests.MessagingWire.MessagingWireFixtures.Dph2(dpk2, 4112);
        var initiation = new VerifiedDph2Initiation(
            dph2,
            new VerifiedDpk2Offering(
                dpk2,
                MessagingWireCryptographicInputs.ComputeExactDpk2Hash(dpk2)),
            MessagingWireCryptographicInputs.ComputeDph2TranscriptHash(dpk2, dph2),
            MessagingWireCryptographicInputs.ComputeDph2FullReplayHash(dph2),
            MessagingWireCryptographicInputs.ComputeDph2ClaimBinding(dph2),
            Bytes(32, 0xc6));
        using var handoff = new VerifiedInitialSessionPreKeyClaim(
            Dpk2PrekeyKind.LastResort,
            dph2.LastResortUseCounter,
            dph2.ClaimOperationId.Span,
            dph2.SessionId.Span,
            Bytes(32, 0xe3),
            Bytes(32, 0xe4),
            initiation.FullReplayHash.Span,
            [],
            dpk2.MlKemPrekeyId.Span,
            initiation);

        using var reservation = handoff.ConsumeForDevicePreKeyOwner();
        Assert.Equal(Dpk2PrekeyKind.LastResort, reservation.Kind);
        Assert.Equal(dph2.LastResortUseCounter, reservation.LastResortUseCounter);
        Assert.Empty(reservation.X25519PreKeyId.ToArray());

        var protocolClaim = VerifiedPreKeyClaimCapability.CreateFromVerifiedInitialSession(handoff);
        var protocol = protocolClaim.Consume();
        Assert.Null(protocol.X25519PreKeyId);
        Assert.Equal(dpk2.MlKemPrekeyId.ToArray(), protocol.MlKemPreKeyId);
    }

    private static async Task AssertCodeAsync(
        string code,
        Func<ValueTask<VerifiedXpc1PreKeyClaimReceipt>> action)
    {
        var error = await Assert.ThrowsAsync<Xpc1PreKeyClaimReceiptException>(() => action().AsTask());
        Assert.Equal(code, error.Code);
    }

    private sealed class Fixture
    {
        private Fixture(ContactNetworkAuthorityVerifierTests.Fixture core)
        {
            Core = core;
            Bundle = core.Identity.Promote(core.Identity.Dcr);
            Xps1 = ContactCodec.DecodeXps1(Bundle.Bundle.FieldSpan(12).Slice(5, 352));
        }

        internal ContactNetworkAuthorityVerifierTests.Fixture Core { get; }
        internal VerifiedContactNetworkAuthority Authority { get; private set; } = null!;
        internal VerifiedContactBundleClosure Bundle { get; }
        internal ContactCodec.Xps1Record Xps1 { get; }
        internal VerifiedContactServicePlacement Placement { get; private set; } = null!;
        internal Dpk2Record Dpk2 { get; private set; } = null!;
        internal Xpk1Request Request { get; private set; } = null!;
        internal Xpc1Result Result { get; private set; } = null!;

        internal static async Task<Fixture> CreateAsync(bool repeatReplicaFailureDomain = false)
        {
            var fixture = new Fixture(ContactNetworkAuthorityVerifierTests.Fixture.Create(
                repeatReplicaFailureDomain: repeatReplicaFailureDomain));
            fixture.Authority = await fixture.Core.VerifyAsync();
            fixture.Placement = ContactServicePlacementFactory.Create(
                fixture.Core.CurrentNetwork, ContactServiceRequestKind.ClaimPreKey,
                fixture.Xps1.ServiceCapability);
            fixture.Dpk2 = fixture.BuildDpk2();
            fixture.Request = fixture.BuildRequest();
            fixture.Result = fixture.BuildResult(fixture.Request, fixture.Dpk2);
            return fixture;
        }

        internal ValueTask<VerifiedXpc1PreKeyClaimReceipt> VerifyAsync(
            Xpk1Request? request = null,
            Xpc1Result? result = null,
            VerifiedContactServicePlacement? placement = null,
            FixedClock? clock = null) =>
            Xpc1PreKeyClaimReceiptVerifier.VerifyAsync(
                request ?? Request, result ?? Result, placement ?? Placement, Authority, Bundle,
                new OnionTrustedTimeAuthority(clock ?? new FixedClock(
                    new OnionMonotonicReading(Core.BootId, 1_003))), default);

        internal Xpk1Request BuildRequest(
            byte[]? networkId = null,
            byte[]? serviceCapability = null,
            byte[]? dcb1Hash = null,
            byte[]? xps1Hash = null,
            byte[]? responderDeviceId = null,
            byte[]? senderEphemeralCommitment = null)
        {
            var bytes = Xpk1Codec.Encode(
                networkId ?? Core.Network,
                Bytes(32, 0x71),
                Placement.ViewHash.Span,
                Placement.PlacementHash.Span,
                29, 60,
                serviceCapability ?? Xps1.ServiceCapability,
                dcb1Hash ?? Bundle.Bundle.ArtifactHash.ToArray(),
                xps1Hash ?? SHA256.HashData(Xps1.CanonicalBytes),
                responderDeviceId ?? Authority.RecipientDeviceId.ToArray(),
                senderEphemeralCommitment ?? Bytes(32, 0x72));
            return Xpk1Codec.Decode(bytes);
        }

        internal Dpk2Record BuildDpk2(DpkOverrides? change = null)
        {
            change ??= new DpkOverrides();
            var certificate = Core.Identity.VerifiedRecipient.Certificate;
            Dpk2Record Create(ReadOnlySpan<byte> signedXSignature, ReadOnlySpan<byte> mlKemSignature,
                ReadOnlySpan<byte> bundleSignature) => new(
                change.NetworkId ?? Core.Network,
                change.AccountId ?? certificate.AccountHash.ToArray(),
                change.DeviceId ?? certificate.DeviceId.ToArray(),
                change.DeviceGeneration ?? certificate.DeviceGeneration,
                change.Dpd1Reference ?? Authority.RecipientDpd1Reference.ToArray(),
                Core.Identity.Directory.Record.DirectoryGeneration,
                change.Dmd1Hash ?? Core.Identity.Directory.Record.RecordHash.ToArray(),
                change.ServiceGeneration ?? Xps1.ServiceGeneration,
                1, Bytes(32, 0x73), 1, 20, 20, 70,
                change.AgreementKey ?? certificate.DeviceX25519PublicKey.ToArray(),
                Bytes(32, 0x74), Bytes(32, 0x75), signedXSignature,
                Bytes(32, 0x76), Bytes(32, 0x77),
                Bytes(32, 0x78), Bytes(1184, 0x79), Dpk2PrekeyKind.OneTime, 0,
                mlKemSignature, bundleSignature);

            var unsigned = Create(new byte[64], new byte[64], new byte[64]);
            var signedX = PublicKeyAuth.SignDetached(
                MessagingWireCryptographicInputs.GetX25519SignedPrekeySignatureInput(unsigned),
                Core.Identity.Device.PrivateKey);
            var mlKem = PublicKeyAuth.SignDetached(
                MessagingWireCryptographicInputs.GetMlKemPrekeySignatureInput(unsigned),
                Core.Identity.Device.PrivateKey);
            var signedPrekeys = Create(signedX, mlKem, new byte[64]);
            var bundle = PublicKeyAuth.SignDetached(
                MessagingWireCryptographicInputs.GetPrekeyBundleSignatureInput(signedPrekeys),
                Core.Identity.Device.PrivateKey);
            if (change.FakeBundleSignature) bundle[0] ^= 0xff;
            return Create(signedX, mlKem, bundle);
        }

        internal Xpc1Result BuildResult(
            Xpk1Request request,
            Dpk2Record dpk2,
            Xpc1Status status = Xpc1Status.Claimed,
            byte[]? dmd1Hash = null,
            byte[]? drs1Reference = null,
            ulong claimCommitGeneration = 1,
            ulong serverTime = 30,
            bool fakeReplicaSignature = false,
            bool fakeManifestSignature = false)
        {
            var exactDpk2 = Dpk2Codec.Encode(dpk2);
            var selectedId = dpk2.OneTimeX25519PrekeyId.ToArray();
            var xps1Reference = PreKeyInventoryTestData.Reference("XPS1", SHA256.HashData(Xps1.CanonicalBytes));
            var manifest = PreKeyInventoryTestData.CreateClaimManifest(
                dpk2, Xps1.ServiceCapability, xps1Reference,
                PreKeyInventoryTestData.Reference("DRS1", Authority.RecipientDrs1ReferenceSpan[6..]),
                Core.Identity.Device.PrivateKey);
            var exactXpi1 = manifest.ExactXpi1.ToArray();
            if (fakeManifestSignature) exactXpi1[^1] ^= 0xff;
            var receiptHash = Xpc1Codec.ComputeClaimReceiptHash(
                request.RequestHash.Span, exactDpk2, exactXpi1, selectedId, claimCommitGeneration, 0);
            var dpk2Hash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(dpk2);
            var xpi1Hash = Xpi1Codec.ComputeHash(exactXpi1);
            var transcript = Join(
                request.RequestHash.ToArray(), dpk2Hash, xpi1Hash, selectedId,
                U64(claimCommitGeneration), U16(0));
            var signatureInput = ContactCodec.SignatureInput(
                "Deep/ContactResolver/V1/prekey-claim-commit", transcript);
            var rows = Core.ReplicaIdentities
                .OrderBy(static replica => replica.NodeId, ByteArrayComparer.Instance)
                .Select(replica => Join(replica.NodeId,
                    PublicKeyAuth.SignDetached(signatureInput, replica.Key.PrivateKey)))
                .ToArray();
            if (fakeReplicaSignature) rows[0][32] ^= 0xff;
            var receipts = Join([2], rows[0], rows[1]);
            ReadOnlyMemory<byte>[] payload =
            [
                exactDpk2, selectedId, receiptHash,
                dmd1Hash ?? Core.Identity.Directory.Record.RecordHash.ToArray(),
                drs1Reference ?? PreKeyInventoryTestData.Reference("DRS1", Authority.RecipientDrs1ReferenceSpan[6..]),
                U64(dpk2.PrekeyServiceGeneration), U64(dpk2.ExpiresAt), U16(0),
                U64(claimCommitGeneration), receipts,
                exactXpi1, U16(manifest.InventoryIndex), manifest.InclusionProof,
            ];
            var wire = Xpc1Codec.Encode(
                request.CanonicalBytes.Span, status, ContactServiceMutationOutcome.DurablyCommitted,
                serverTime, 0, ContactServicePaddingClass.Bytes4096, payload);
            return Xpc1Codec.Decode(wire, request.CanonicalBytes.Span);
        }

        internal Xpc1Result BuildUnclaimedResult()
        {
            var wire = Xpc1Codec.Encode(
                Request.CanonicalBytes.Span, Xpc1Status.PreKeysUnavailable,
                ContactServiceMutationOutcome.None, 30, 0,
                ContactServicePaddingClass.Bytes256, []);
            return Xpc1Codec.Decode(wire, Request.CanonicalBytes.Span);
        }

        internal Dph2Record BuildDph2(byte[] claimReceiptHash, Xpk1Request? request = null)
        {
            request ??= Request;
            return new Dph2Record(
                Core.Network, Bytes(32, 0xc1), Bytes(32, 0xc2), 1,
                Reference("DPD1", 0xc3),
                Dpk2.ResponderAccountId.Span, Dpk2.ResponderDeviceId.Span,
                Dpk2.ResponderDeviceGeneration,
                MessagingWireCryptographicInputs.ComputeExactDpk2Hash(Dpk2),
                request.OperationId.Span, claimReceiptHash, 0,
                Bytes(32, 0xc4), Bytes(32, 0xc5),
                Dph2SelectedPrekey.OneTime(
                    Dpk2.SignedX25519PrekeyId.Span,
                    Dpk2.OneTimeX25519PrekeyId.Span,
                    Dpk2.MlKemPrekeyId.Span),
                Bytes(1088, 0xc6), Bytes(32, 0xc7), Bytes(24, 0xc8),
                Dph2InitialCiphertext.Import(Bytes(4112, 0xc9)));
        }
    }

    private sealed record DpkOverrides(
        byte[]? NetworkId = null,
        byte[]? AccountId = null,
        byte[]? DeviceId = null,
        ulong? DeviceGeneration = null,
        byte[]? Dpd1Reference = null,
        byte[]? AgreementKey = null,
        byte[]? Dmd1Hash = null,
        ulong? ServiceGeneration = null,
        bool FakeBundleSignature = false);

    internal sealed class FixedClock(OnionMonotonicReading reading) : IOnionMonotonicClock
    {
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new OnionMonotonicReading(reading.BootId.Span, reading.SampleSeconds));
        }
    }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }

    private static byte[] Reference(string magic, byte fill)
    {
        var value = new byte[38];
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4), 1);
        value.AsSpan(6).Fill(fill);
        return value;
    }

    private static byte[] Bytes(int length, byte fill)
    {
        var value = new byte[length];
        value.AsSpan().Fill(fill);
        return value;
    }

    private static byte[] U16(ushort value)
    {
        var output = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(output, value);
        return output;
    }

    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    private static byte[] Join(params byte[][] values)
    {
        var output = new byte[values.Sum(static value => value.Length)];
        var offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(output, offset);
            offset += value.Length;
        }
        return output;
    }
}
