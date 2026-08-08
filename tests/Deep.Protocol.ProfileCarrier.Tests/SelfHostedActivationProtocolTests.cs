using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.DeepExtension.SelfHostedProfiles;

namespace Deep.Protocol.ProfileCarrier.Tests;

public sealed class SelfHostedActivationProtocolTests
{
    private static readonly byte[] AccountGeneration = Bytes(0x31, 32);

    [Fact]
    public void Descriptor_exposes_exact_verified_state_with_defensive_copies()
    {
        var dpf = Compose(SyntheticProfileFixture.Parts(bridgeCount: 2, contactsPerBridge: 2));
        var expectedDpf = SHA256.HashData(dpf);
        var descriptor = VerifyDescriptor(dpf);

        Assert.Equal(expectedDpf, descriptor.ExactDpfSha256.ToArray());
        Assert.Equal(2UL, descriptor.LatestVerifiedDelegation.Sequence);
        Assert.Equal(3UL, descriptor.LatestBridgeSequence);
        Assert.Equal(2, descriptor.OrderedContacts.Count);
        Assert.Equal(2, descriptor.LatestVerifiedDelegation.OnlineThreshold);

        var exportedDpf = descriptor.ExactDpfSha256.ToArray();
        var exportedContact = descriptor.OrderedContacts[0].EntryId.ToArray();
        var exportedSigner = descriptor.LatestVerifiedDelegation.OnlineSigners[0].PublicKey.ToArray();
        exportedDpf.AsSpan().Fill(0xff);
        exportedContact.AsSpan().Fill(0xff);
        exportedSigner.AsSpan().Fill(0xff);

        Assert.Equal(expectedDpf, descriptor.ExactDpfSha256.ToArray());
        Assert.DoesNotContain((byte)0xff, descriptor.OrderedContacts[0].EntryId.ToArray());
        Assert.DoesNotContain((byte)0xff,
            descriptor.LatestVerifiedDelegation.OnlineSigners[0].PublicKey.ToArray());
    }

    [Fact]
    public void Only_activation_gate_can_create_the_runtime_authority_capability()
    {
        var assembly = typeof(SelfHostedActivationGate).Assembly;
        Assert.DoesNotContain(
            assembly.ExportedTypes,
            static type => type.Name == "SelfHostedActivationDescriptorVerifier");
        Assert.Empty(typeof(VerifiedSelfHostedActivationDescriptor).GetConstructors());
        var publicFactories = assembly.ExportedTypes
            .SelectMany(static type => type.GetMethods())
            .Where(static method =>
                !method.IsSpecialName &&
                method.ReturnType.IsGenericType &&
                method.ReturnType.GetGenericTypeDefinition() == typeof(ValueTask<>) &&
                method.ReturnType.GenericTypeArguments[0] ==
                    typeof(VerifiedSelfHostedActivationDescriptor))
            .ToArray();
        Assert.NotEmpty(publicFactories);
        Assert.All(publicFactories, static method =>
        {
            Assert.Equal(typeof(SelfHostedActivationGate), method.DeclaringType);
            Assert.EndsWith("Async", method.Name, StringComparison.Ordinal);
        });
        Assert.Equal(
            typeof(ValueTask<bool>),
            typeof(ISelfHostedActivationCommitter).GetMethod("TryCommitAsync")!.ReturnType);
    }

    [Fact]
    public async Task Initial_activation_requires_exact_single_use_consent()
    {
        var dpf = Compose(SyntheticProfileFixture.Parts());
        var descriptor = VerifyDescriptor(dpf);
        var committer = new InMemoryActivationCommitter();
        var consent = Consent(descriptor, 0x41);

        var accepted = await SelfHostedActivationGate.ActivateInitialAsync(
            dpf, Options(), AccountGeneration, consent, committer,
            SyntheticProfileFixture.Verifier());
        Assert.Equal(descriptor.ExactDpfSha256.ToArray(), accepted.ExactDpfSha256.ToArray());
        Assert.Equal(dpf, committer.ActiveDpf);
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await
            SelfHostedActivationGate.ActivateInitialAsync(
            dpf, Options(), AccountGeneration, consent, committer,
            SyntheticProfileFixture.Verifier()));

        var wrongAccount = Bytes(0x91, 32);
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await
            SelfHostedActivationGate.ActivateInitialAsync(
            dpf, Options(), wrongAccount, Consent(descriptor, 0x42),
            new InMemoryActivationCommitter(), SyntheticProfileFixture.Verifier()));
        var wrongCandidate = new SelfHostedSwitchConsent(
            Bytes(0x43, 32), AccountGeneration, Bytes(0x81, 32),
            descriptor.GenesisFingerprintSha256.Span);
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await
            SelfHostedActivationGate.ActivateInitialAsync(
            dpf, Options(), AccountGeneration, wrongCandidate,
            new InMemoryActivationCommitter(), SyntheticProfileFixture.Verifier()));
        var wrongGenesis = new SelfHostedSwitchConsent(
            Bytes(0x44, 32), AccountGeneration, descriptor.ExactDpfSha256.Span,
            Bytes(0x82, 32));
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await
            SelfHostedActivationGate.ActivateInitialAsync(
            dpf, Options(), AccountGeneration, wrongGenesis,
            new InMemoryActivationCommitter(), SyntheticProfileFixture.Verifier()));
    }

    [Fact]
    public async Task Activation_commit_is_atomic_boundary_for_consent_and_candidate_install()
    {
        var dpf = Compose(SyntheticProfileFixture.Parts());
        var descriptor = VerifyDescriptor(dpf);
        var rejecting = new RejectingActivationCommitter();

        await Assert.ThrowsAsync<InvalidOperationException>(async () => await
            SelfHostedActivationGate.ActivateInitialAsync(
            dpf, Options(), AccountGeneration, Consent(descriptor, 0x48), rejecting,
            SyntheticProfileFixture.Verifier()));
        Assert.Equal(1, rejecting.Calls);

        var throwing = new ThrowingActivationCommitter();
        await Assert.ThrowsAsync<IOException>(async () => await
            SelfHostedActivationGate.ActivateInitialAsync(
                dpf, Options(), AccountGeneration, Consent(descriptor, 0x4a), throwing,
                SyntheticProfileFixture.Verifier()));
        Assert.Equal(1, throwing.Calls);

        var canceling = new CancelingActivationCommitter();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await
            SelfHostedActivationGate.ActivateInitialAsync(
                dpf, Options(), AccountGeneration, Consent(descriptor, 0x4b), canceling,
                SyntheticProfileFixture.Verifier()));
        Assert.Equal(1, canceling.Calls);

        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        var notCalled = new RejectingActivationCommitter();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await
            SelfHostedActivationGate.ActivateInitialAsync(
                dpf, Options(), AccountGeneration, Consent(descriptor, 0x4c), notCalled,
                SyntheticProfileFixture.Verifier(), canceled.Token));
        Assert.Equal(0, notCalled.Calls);

        var committing = new InMemoryActivationCommitter();
        await SelfHostedActivationGate.ActivateInitialAsync(
            dpf, Options(), AccountGeneration, Consent(descriptor, 0x49), committing,
            SyntheticProfileFixture.Verifier());
        Assert.Equal(dpf, committing.ActiveDpf);
        Assert.Equal(SelfHostedActivationCommitKind.Initial, committing.LastCommit!.Kind);
        Assert.Equal(dpf, committing.LastCommit.CandidateExactDpf.ToArray());
    }

    [Fact]
    public async Task Public_entrypoints_freeze_caller_buffers_before_verifier_callbacks()
    {
        var dpf = Compose(SyntheticProfileFixture.Parts());
        var original = dpf.ToArray();
        var membership = new MutatingMembershipVerifier(
            SyntheticProfileFixture.Verifier(), dpf);
        var descriptor = SelfHostedActivationDescriptorVerifier.VerifyExact(
            dpf, Options(), membership);
        Assert.Equal(SHA256.HashData(original), descriptor.ExactDpfSha256.ToArray());
        Assert.All(dpf, static value => Assert.Equal(0xff, value));

        var runtimeVerifier = new SyntheticRuntimeSignatureVerifier();
        var encoded = SelfHostedRuntimeEnvelopeCodec.Encode(
            SignedEnvelope(descriptor, runtimeVerifier, 1, new byte[32], ["mau2"]));
        var originalRuntime = encoded.ToArray();
        var verified = SelfHostedRuntimeEnvelopeVerifier.VerifyExact(
            encoded, descriptor, 1_100, 2,
            new MutatingRuntimeVerifier(runtimeVerifier, encoded));
        Assert.Equal(SHA256.HashData(originalRuntime), verified.EnvelopeSha256.ToArray());
        Assert.All(encoded, static value => Assert.Equal(0xee, value));

        var currentDpf = Compose(SyntheticProfileFixture.Parts(bridgeCount: 1));
        var candidateDpf = Compose(SyntheticProfileFixture.Parts(bridgeCount: 2));
        var expectedCandidate = candidateDpf.ToArray();
        var current = VerifyDescriptor(currentDpf);
        var committer = new InMemoryActivationCommitter();
        var accepted = await SelfHostedActivationGate.ActivateUpdateAsync(
            currentDpf,
            Options(),
            ActivationLkg(current),
            candidateDpf,
            Options(),
            AccountGeneration,
            null,
            committer,
            new MutatingMembershipVerifier(
                SyntheticProfileFixture.Verifier(), currentDpf, candidateDpf));
        Assert.Equal(SHA256.HashData(expectedCandidate), accepted.ExactDpfSha256.ToArray());
        Assert.Equal(expectedCandidate, committer.ActiveDpf);
        Assert.All(currentDpf, static value => Assert.Equal(0xff, value));
        Assert.All(candidateDpf, static value => Assert.Equal(0xff, value));
    }

    [Fact]
    public void Oversized_inputs_fail_before_verifier_callbacks_or_unbounded_enumeration()
    {
        var membership = new CountingMembershipVerifier();
        var error = Assert.Throws<ProfileCarrierException>(() =>
            SelfHostedActivationDescriptorVerifier.VerifyExact(
                new byte[ProfileCarrierLimits.MaximumFilePayloadBytes + 1], Options(), membership));
        Assert.Equal(ProfileCarrierError.BoundsExceeded, error.Error);
        Assert.Equal(0, membership.Calls);

        var descriptor = VerifyDescriptor(Compose(SyntheticProfileFixture.Parts()));
        var runtime = new CountingRuntimeVerifier();
        Assert.Throws<InvalidDataException>(() => SelfHostedRuntimeEnvelopeVerifier.VerifyExact(
            new byte[SelfHostedRuntimeEnvelopeContract.MaximumEncodedBytes + 1], descriptor,
            1_100, 2, runtime));
        Assert.Equal(0, runtime.Calls);

        Assert.Throws<ArgumentException>(() => new SelfHostedRuntimeSignature(
            Bytes(0x10, MembershipLimits.SignerIdLength),
            new byte[SelfHostedRuntimeEnvelopeContract.MaximumSignatureBytes + 1]));
        var valid = SignedEnvelope(
            descriptor, new SyntheticRuntimeSignatureVerifier(), 1, new byte[32], ["mau2"]);
        Assert.Throws<ArgumentException>(() => CopyEnvelope(
            valid, capabilities: HostileCapabilities()));
    }

    [Fact]
    public async Task Same_genesis_update_requires_exact_current_lkg_and_forward_transition()
    {
        var currentDpf = Compose(SyntheticProfileFixture.Parts(bridgeCount: 1));
        var candidateDpf = Compose(SyntheticProfileFixture.Parts(bridgeCount: 2));
        var current = VerifyDescriptor(currentDpf);
        var lkg = ActivationLkg(current);

        var accepted = await SelfHostedActivationGate.ActivateUpdateAsync(
            currentDpf, Options(), lkg, candidateDpf, Options(), AccountGeneration,
            null, new InMemoryActivationCommitter(), SyntheticProfileFixture.Verifier());
        Assert.Equal(3UL, accepted.LatestBridgeSequence);

        await Assert.ThrowsAsync<InvalidDataException>(async () => await
            SelfHostedActivationGate.ActivateUpdateAsync(
            candidateDpf, Options(), ActivationLkg(accepted), currentDpf, Options(),
            AccountGeneration, null, new InMemoryActivationCommitter(),
            SyntheticProfileFixture.Verifier()));
        var wrongLkg = new SelfHostedActivationLastKnownGood(
            AccountGeneration, Bytes(0x82, 32), current.GenesisFingerprintSha256.Span,
            current.LatestBridgeSequence, current.LatestBridgeSha256.Span);
        await Assert.ThrowsAsync<InvalidDataException>(async () => await
            SelfHostedActivationGate.ActivateUpdateAsync(
            currentDpf, Options(), wrongLkg, candidateDpf, Options(), AccountGeneration,
            null, new InMemoryActivationCommitter(), SyntheticProfileFixture.Verifier()));
    }

    [Fact]
    public async Task Other_genesis_requires_consent_bound_to_exact_candidate()
    {
        var currentDpf = Compose(SyntheticProfileFixture.Parts());
        var candidateDpf = Compose(PartsForNetwork(0xd0));
        var current = VerifyDescriptor(currentDpf);
        var candidate = VerifyDescriptor(candidateDpf);

        await Assert.ThrowsAsync<InvalidDataException>(async () => await
            SelfHostedActivationGate.ActivateUpdateAsync(
            currentDpf, Options(), ActivationLkg(current), candidateDpf, Options(),
            AccountGeneration, null, new InMemoryActivationCommitter(),
            SyntheticProfileFixture.Verifier()));

        var accepted = await SelfHostedActivationGate.ActivateUpdateAsync(
            currentDpf, Options(), ActivationLkg(current), candidateDpf, Options(),
            AccountGeneration, Consent(candidate, 0x51), new InMemoryActivationCommitter(),
            SyntheticProfileFixture.Verifier());
        Assert.Equal(candidate.GenesisFingerprintSha256.ToArray(),
            accepted.GenesisFingerprintSha256.ToArray());
    }

    [Fact]
    public void Runtime_envelope_round_trips_and_accepts_private_https_origins()
    {
        var descriptor = VerifyDescriptor(Compose(SyntheticProfileFixture.Parts()));
        var signatureVerifier = new SyntheticRuntimeSignatureVerifier();
        var envelope = SignedEnvelope(descriptor, signatureVerifier, 1, new byte[32], ["mau2"]);
        var encoded = SelfHostedRuntimeEnvelopeCodec.Encode(envelope);

        var decoded = SelfHostedRuntimeEnvelopeCodec.Decode(encoded);
        var verified = SelfHostedRuntimeEnvelopeVerifier.VerifyExact(
            encoded, descriptor, SyntheticProfileFixture.VerificationTime,
            SyntheticProfileFixture.Protocol, signatureVerifier);

        Assert.Equal("https://192.168.50.10:8443/", decoded.Coordinator.Origin);
        Assert.Equal(SelfHostedRuntimeTransitionDecision.GenesisAccepted, verified.Decision);
        Assert.Equal(encoded, SelfHostedRuntimeEnvelopeCodec.Encode(decoded));

        var exported = decoded.Coordinator.CurrentSpkiSha256.ToArray();
        exported.AsSpan().Fill(0xff);
        Assert.DoesNotContain((byte)0xff, decoded.Coordinator.CurrentSpkiSha256.ToArray());
    }

    [Fact]
    public void Runtime_envelope_rejects_capability_and_cross_network_tampering()
    {
        var descriptor = VerifyDescriptor(Compose(SyntheticProfileFixture.Parts()));
        var signatureVerifier = new SyntheticRuntimeSignatureVerifier();
        var signed = SignedEnvelope(descriptor, signatureVerifier, 1, new byte[32], ["mau2"]);

        var capabilityTamper = CopyEnvelope(signed, capabilities: ["mau2", "storage"]);
        Assert.Throws<InvalidDataException>(() => SelfHostedRuntimeEnvelopeVerifier.VerifyExact(
            SelfHostedRuntimeEnvelopeCodec.Encode(capabilityTamper), descriptor,
            SyntheticProfileFixture.VerificationTime, SyntheticProfileFixture.Protocol,
            signatureVerifier));

        var network = signed.NetworkId.ToArray();
        network[0] ^= 0x01;
        var networkTamper = CopyEnvelope(signed, networkId: network);
        Assert.Throws<InvalidDataException>(() => SelfHostedRuntimeEnvelopeVerifier.VerifyExact(
            SelfHostedRuntimeEnvelopeCodec.Encode(networkTamper), descriptor,
            SyntheticProfileFixture.VerificationTime, SyntheticProfileFixture.Protocol,
            signatureVerifier));
    }

    [Fact]
    public void Runtime_envelope_rejects_rollback_fork_and_expiry()
    {
        var descriptor = VerifyDescriptor(Compose(SyntheticProfileFixture.Parts()));
        var signatureVerifier = new SyntheticRuntimeSignatureVerifier();
        var first = SignedEnvelope(descriptor, signatureVerifier, 1, new byte[32], ["mau2"]);
        var firstEncoded = SelfHostedRuntimeEnvelopeCodec.Encode(first);
        var firstVerified = SelfHostedRuntimeEnvelopeVerifier.VerifyExact(
            firstEncoded, descriptor, 1_100, 2, signatureVerifier);
        var lkg = firstVerified.ToLastKnownGood();
        var second = SignedEnvelope(
            descriptor, signatureVerifier, 2, firstVerified.EnvelopeSha256.Span, ["mau2"]);
        var secondVerified = SelfHostedRuntimeEnvelopeVerifier.VerifyExact(
            SelfHostedRuntimeEnvelopeCodec.Encode(second), descriptor, 1_100, 2,
            signatureVerifier, lkg);
        Assert.Equal(SelfHostedRuntimeTransitionDecision.Forward, secondVerified.Decision);

        var generationTwoLkg = secondVerified.ToLastKnownGood();
        Assert.Throws<InvalidDataException>(() => SelfHostedRuntimeEnvelopeVerifier.VerifyExact(
            firstEncoded, descriptor, 1_100, 2, signatureVerifier, generationTwoLkg));

        var fork = SignedEnvelope(descriptor, signatureVerifier, 2, Bytes(0xe0, 32), ["mau2"]);
        Assert.Throws<InvalidDataException>(() => SelfHostedRuntimeEnvelopeVerifier.VerifyExact(
            SelfHostedRuntimeEnvelopeCodec.Encode(fork), descriptor, 1_100, 2,
            signatureVerifier, lkg));
        Assert.Throws<InvalidDataException>(() => SelfHostedRuntimeEnvelopeVerifier.VerifyExact(
            firstEncoded, descriptor, 1_501, 2, signatureVerifier));
        Assert.Throws<InvalidDataException>(() => SelfHostedRuntimeEnvelopeVerifier.VerifyExact(
            firstEncoded, descriptor, 1_049, 2, signatureVerifier));
    }

    [Fact]
    public void Runtime_successor_rejects_security_state_reset_and_spki_abba()
    {
        var descriptor = VerifyDescriptor(Compose(SyntheticProfileFixture.Parts()));
        var verifier = new SyntheticRuntimeSignatureVerifier();
        var first = SelfHostedRuntimeEnvelopeVerifier.VerifyExact(
            SelfHostedRuntimeEnvelopeCodec.Encode(
                SignedEnvelope(descriptor, verifier, 1, new byte[32], ["mau2"])),
            descriptor, 1_100, 2, verifier);
        var lkg = first.ToLastKnownGood();

        var topologyReset = SignedEnvelope(
            descriptor, verifier, 2, first.EnvelopeSha256.Span, ["mau2"],
            static value => CopyEnvelope(
                value, topologyGeneration: 1, topologySha256: Bytes(0xe1, 32)));
        Assert.Throws<InvalidDataException>(() => VerifyRuntime(topologyReset, descriptor, verifier, lkg));

        var revocationFork = SignedEnvelope(
            descriptor, verifier, 2, first.EnvelopeSha256.Span, ["mau2"],
            static value => CopyEnvelope(
                value,
                revocationGeneration: 1,
                previousRevocationHeadSha256: new byte[32],
                revocationHeadSha256: Bytes(0xe2, 32)));
        Assert.Throws<InvalidDataException>(() => VerifyRuntime(revocationFork, descriptor, verifier, lkg));

        var revocationWindowFork = SignedEnvelope(
            descriptor, verifier, 2, first.EnvelopeSha256.Span, ["mau2"],
            value => CopyEnvelope(
                value,
                revocationGeneration: first.Envelope.RevocationGeneration,
                previousRevocationHeadSha256:
                    first.Envelope.PreviousRevocationHeadSha256.ToArray(),
                revocationHeadSha256: first.Envelope.RevocationHeadSha256.ToArray(),
                revocationIssuedAtUnixSeconds:
                    first.Envelope.RevocationIssuedAtUnixSeconds,
                revocationExpiresAtUnixSeconds:
                    first.Envelope.RevocationExpiresAtUnixSeconds - 1));
        Assert.Throws<InvalidDataException>(() =>
            VerifyRuntime(revocationWindowFork, descriptor, verifier, lkg));

        var epochFork = SignedEnvelope(
            descriptor, verifier, 2, first.EnvelopeSha256.Span, ["mau2"],
            static value => CopyEnvelope(
                value,
                currentEpoch: new SelfHostedRuntimeEpoch(1, 1, 1_000, 1_299)));
        Assert.Throws<InvalidDataException>(() => VerifyRuntime(epochFork, descriptor, verifier, lkg));

        var abba = SignedEnvelope(
            descriptor, verifier, 2, first.EnvelopeSha256.Span, ["mau2"],
            static value => CopyEnvelope(
                value,
                coordinator: new SelfHostedRuntimeEndpoint(
                    value.Coordinator.Origin,
                    value.Coordinator.NextSpkiSha256.Span,
                    value.Coordinator.CurrentSpkiSha256.Span)));
        Assert.Throws<InvalidDataException>(() => VerifyRuntime(abba, descriptor, verifier, lkg));
    }

    [Fact]
    public void Runtime_shape_rejects_terminal_successor_states()
    {
        var descriptor = VerifyDescriptor(Compose(SyntheticProfileFixture.Parts()));
        var valid = SignedEnvelope(
            descriptor, new SyntheticRuntimeSignatureVerifier(), 1, new byte[32], ["mau2"]);

        Assert.Throws<InvalidDataException>(() => SelfHostedRuntimeEnvelopeCodec.Encode(
            CopyEnvelope(
                valid,
                generation: ulong.MaxValue,
                previousEnvelopeSha256: Bytes(0x11, 32))));
        Assert.Throws<InvalidDataException>(() => SelfHostedRuntimeEnvelopeCodec.Encode(
            CopyEnvelope(valid, topologyGeneration: ulong.MaxValue)));
        Assert.Throws<InvalidDataException>(() => SelfHostedRuntimeEnvelopeCodec.Encode(
            CopyEnvelope(valid, revocationGeneration: ulong.MaxValue)));
        Assert.Throws<InvalidDataException>(() => SelfHostedRuntimeEnvelopeCodec.Encode(
            CopyEnvelope(
                valid,
                currentEpoch: new SelfHostedRuntimeEpoch(
                    ulong.MaxValue - 1, ulong.MaxValue - 1, 1_000, 1_300),
                nextEpoch: new SelfHostedRuntimeEpoch(
                    ulong.MaxValue, ulong.MaxValue, 1_200, 1_500))));
    }

    [Fact]
    public void Runtime_codec_and_verifier_fail_closed_for_malformed_mutations()
    {
        var descriptor = VerifyDescriptor(Compose(SyntheticProfileFixture.Parts()));
        var signatureVerifier = new SyntheticRuntimeSignatureVerifier();
        var encoded = SelfHostedRuntimeEnvelopeCodec.Encode(
            SignedEnvelope(descriptor, signatureVerifier, 1, new byte[32], ["mau2"]));

        for (var length = 0; length < encoded.Length; length += Math.Max(1, encoded.Length / 19))
        {
            Assert.Throws<InvalidDataException>(() =>
                SelfHostedRuntimeEnvelopeCodec.Decode(encoded.AsSpan(0, length)));
        }
        var random = new Random(0x53485231);
        for (var index = 0; index < 64; index++)
        {
            var mutated = encoded.ToArray();
            var offset = random.Next(mutated.Length);
            mutated[offset] ^= (byte)random.Next(1, 256);
            Assert.Throws<InvalidDataException>(() =>
                SelfHostedRuntimeEnvelopeVerifier.VerifyExact(
                    mutated, descriptor, 1_100, 2, signatureVerifier));
        }
    }

    private static SelfHostedActivationLastKnownGood ActivationLkg(
        VerifiedSelfHostedActivationDescriptor descriptor) => new(
            AccountGeneration,
            descriptor.ExactDpfSha256.Span,
            descriptor.GenesisFingerprintSha256.Span,
            descriptor.LatestBridgeSequence,
            descriptor.LatestBridgeSha256.Span);

    private static SelfHostedSwitchConsent Consent(
        VerifiedSelfHostedActivationDescriptor descriptor,
        int seed) => new(
            Bytes(seed, 32), AccountGeneration, descriptor.ExactDpfSha256.Span,
            descriptor.GenesisFingerprintSha256.Span);

    private static VerifiedSelfHostedActivationDescriptor VerifyDescriptor(byte[] dpf) =>
        SelfHostedActivationDescriptorVerifier.VerifyExact(
            dpf, Options(), SyntheticProfileFixture.Verifier());

    private static ProfileCarrierVerificationOptions Options() =>
        ProfileCarrierContractRedTests.Options();

    private static byte[] Compose(SyntheticProfileParts parts) =>
        ProfileCarrierComposer.ComposeExact(
            ProfileCarrierContractRedTests.Input(parts), Options(),
            SyntheticProfileFixture.Verifier()).FilePayload.ToArray();

    private static SyntheticProfileParts PartsForNetwork(int start)
    {
        var verifier = SyntheticProfileFixture.Verifier();
        var genesis = SyntheticProfileFixture.Genesis() with
        {
            NetworkId = Bytes(start, MembershipLimits.NetworkIdLength)
        };
        var canonicalGenesis = MembershipContractCodec.EncodeGenesis(genesis);
        var approvals = SyntheticProfileFixture.Signatures(
            genesis.OfflineRoots, MembershipSignatureDomain.Genesis,
            canonicalGenesis, 3, verifier);
        var delegation = SyntheticProfileFixture.SignedDelegation(
            genesis, canonicalGenesis, verifier);
        var bridges = SyntheticProfileFixture.SignedBridges(
                genesis, canonicalGenesis, delegation, 1, 48, 1, null, verifier)
            .Select(MembershipContractCodec.EncodeSignedBridge)
            .ToArray();
        return new(canonicalGenesis, approvals,
            MembershipContractCodec.EncodeSignedDelegation(delegation), bridges);
    }

    private static SelfHostedRuntimeEnvelope SignedEnvelope(
        VerifiedSelfHostedActivationDescriptor descriptor,
        SyntheticRuntimeSignatureVerifier verifier,
        ulong generation,
        ReadOnlySpan<byte> previousEnvelopeSha256,
        string[] capabilities,
        Func<SelfHostedRuntimeEnvelope, SelfHostedRuntimeEnvelope>? mutation = null)
    {
        var unsigned = Envelope(
            descriptor, generation, previousEnvelopeSha256, capabilities, []);
        unsigned = mutation?.Invoke(unsigned) ?? unsigned;
        var signingBytes = SelfHostedRuntimeEnvelopeCodec.GetSigningBytes(unsigned);
        var signatures = descriptor.LatestVerifiedDelegation.OnlineSigners
            .Take(descriptor.LatestVerifiedDelegation.OnlineThreshold)
            .Select(signer => new SelfHostedRuntimeSignature(
                signer.SignerId.Span,
                verifier.Sign(signer.SignerId.Span, signer.PublicKey.Span, signingBytes)))
            .ToArray();
        return CopyEnvelope(unsigned, signatures: signatures);
    }

    private static SelfHostedRuntimeEnvelope Envelope(
        VerifiedSelfHostedActivationDescriptor descriptor,
        ulong generation,
        ReadOnlySpan<byte> previousEnvelopeSha256,
        string[] capabilities,
        SelfHostedRuntimeSignature[] signatures) => new(
            descriptor.NetworkId.Span,
            descriptor.ExactDpfSha256.Span,
            descriptor.GenesisFingerprintSha256.Span,
            descriptor.LatestVerifiedDelegation.Sequence,
            descriptor.LatestVerifiedDelegation.StatementCommitmentSha256.Span,
            generation,
            previousEnvelopeSha256,
            1_050,
            1_000,
            1_500,
            descriptor.MinimumProtocol,
            descriptor.MaximumProtocol,
            new SelfHostedRuntimeEndpoint(
                "https://192.168.50.10:8443/", Bytes(0x10, 32), Bytes(0x30, 32)),
            new SelfHostedRuntimeEndpoint(
                "https://mau2.home.arpa:9443/", Bytes(0x50, 32), Bytes(0x70, 32)),
            generation,
            Bytes(0x90 + checked((int)generation), 32),
            generation,
            generation == 1
                ? new byte[32]
                : Bytes(0xc0 + checked((int)generation) - 1, 32),
            Bytes(0xc0 + checked((int)generation), 32),
            1_050 + generation - 1,
            1_400,
            new SelfHostedRuntimeEpoch(1, 1, 1_000, 1_300),
            new SelfHostedRuntimeEpoch(2, 2, 1_200, 1_500),
            capabilities,
            signatures);

    private static SelfHostedRuntimeEnvelope CopyEnvelope(
        SelfHostedRuntimeEnvelope value,
        byte[]? networkId = null,
        IEnumerable<string>? capabilities = null,
        IEnumerable<SelfHostedRuntimeSignature>? signatures = null,
        ulong? generation = null,
        byte[]? previousEnvelopeSha256 = null,
        ulong? topologyGeneration = null,
        byte[]? topologySha256 = null,
        ulong? revocationGeneration = null,
        byte[]? previousRevocationHeadSha256 = null,
        byte[]? revocationHeadSha256 = null,
        ulong? revocationIssuedAtUnixSeconds = null,
        ulong? revocationExpiresAtUnixSeconds = null,
        SelfHostedRuntimeEndpoint? coordinator = null,
        SelfHostedRuntimeEndpoint? mau2Ingress = null,
        SelfHostedRuntimeEpoch? currentEpoch = null,
        SelfHostedRuntimeEpoch? nextEpoch = null) => new(
            networkId ?? value.NetworkId.ToArray(),
            value.ExactDpfSha256.Span,
            value.GenesisFingerprintSha256.Span,
            value.DelegationSequence,
            value.DelegationCommitmentSha256.Span,
            generation ?? value.Generation,
            previousEnvelopeSha256 ?? value.PreviousEnvelopeSha256.ToArray(),
            value.IssuedAtUnixSeconds,
            value.ValidFromUnixSeconds,
            value.ValidUntilUnixSeconds,
            value.MinimumProtocol,
            value.MaximumProtocol,
            coordinator ?? value.Coordinator,
            mau2Ingress ?? value.Mau2Ingress,
            topologyGeneration ?? value.TopologyGeneration,
            topologySha256 ?? value.TopologySha256.ToArray(),
            revocationGeneration ?? value.RevocationGeneration,
            previousRevocationHeadSha256 ?? value.PreviousRevocationHeadSha256.ToArray(),
            revocationHeadSha256 ?? value.RevocationHeadSha256.ToArray(),
            revocationIssuedAtUnixSeconds ?? value.RevocationIssuedAtUnixSeconds,
            revocationExpiresAtUnixSeconds ?? value.RevocationExpiresAtUnixSeconds,
            currentEpoch ?? value.CurrentEpoch,
            nextEpoch ?? value.NextEpoch,
            capabilities ?? value.Capabilities.ToArray(),
            signatures ?? value.Signatures);

    private static VerifiedSelfHostedRuntimeEnvelope VerifyRuntime(
        SelfHostedRuntimeEnvelope envelope,
        VerifiedSelfHostedActivationDescriptor descriptor,
        ISelfHostedRuntimeSignatureVerifier verifier,
        SelfHostedRuntimeLastKnownGood lkg) =>
        SelfHostedRuntimeEnvelopeVerifier.VerifyExact(
            SelfHostedRuntimeEnvelopeCodec.Encode(envelope), descriptor,
            1_100, 2, verifier, lkg);

    private static IEnumerable<string> HostileCapabilities()
    {
        for (var index = 0;
             index <= SelfHostedRuntimeEnvelopeContract.MaximumCapabilities;
             index++)
        {
            yield return $"cap-{index:D2}";
        }
        throw new InvalidOperationException("The constructor enumerated beyond its bound.");
    }

    private static byte[] Bytes(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => unchecked((byte)value)).ToArray();

    private sealed class InMemoryActivationCommitter : ISelfHostedActivationCommitter
    {
        private readonly HashSet<string> consumed = new(StringComparer.Ordinal);
        public byte[]? ActiveDpf { get; private set; }
        public SelfHostedActivationCommit? LastCommit { get; private set; }

        public ValueTask<bool> TryCommitAsync(
            SelfHostedActivationCommit commit,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (commit.Consent is not null)
            {
                var key = string.Concat(
                    Convert.ToHexString(commit.Consent.ConsentId.Span), ":",
                    Convert.ToHexString(commit.CurrentAccountGeneration.Span), ":",
                    Convert.ToHexString(commit.CandidateLastKnownGood.ExactDpfSha256.Span), ":",
                    Convert.ToHexString(
                        commit.CandidateLastKnownGood.GenesisFingerprintSha256.Span));
                if (!consumed.Add(key))
                {
                    return ValueTask.FromResult(false);
                }
            }
            ActiveDpf = commit.CandidateExactDpf.ToArray();
            LastCommit = commit;
            return ValueTask.FromResult(true);
        }
    }

    private sealed class RejectingActivationCommitter : ISelfHostedActivationCommitter
    {
        public int Calls { get; private set; }

        public ValueTask<bool> TryCommitAsync(
            SelfHostedActivationCommit commit,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return ValueTask.FromResult(false);
        }
    }

    private sealed class ThrowingActivationCommitter : ISelfHostedActivationCommitter
    {
        public int Calls { get; private set; }

        public ValueTask<bool> TryCommitAsync(
            SelfHostedActivationCommit commit,
            CancellationToken cancellationToken)
        {
            Calls++;
            return ValueTask.FromException<bool>(new IOException("atomic commit failed"));
        }
    }

    private sealed class CancelingActivationCommitter : ISelfHostedActivationCommitter
    {
        public int Calls { get; private set; }

        public ValueTask<bool> TryCommitAsync(
            SelfHostedActivationCommit commit,
            CancellationToken cancellationToken)
        {
            Calls++;
            return ValueTask.FromCanceled<bool>(new CancellationToken(canceled: true));
        }
    }

    private sealed class MutatingMembershipVerifier(
        IMembershipSignatureVerifier inner,
        params byte[][] buffers) : IMembershipSignatureVerifier
    {
        private bool mutated;

        public bool Verify(
            ReadOnlySpan<byte> signerId,
            ReadOnlySpan<byte> publicKey,
            MembershipSignatureDomain domain,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            if (!mutated)
            {
                foreach (var buffer in buffers)
                {
                    buffer.AsSpan().Fill(0xff);
                }
                mutated = true;
            }
            return inner.Verify(signerId, publicKey, domain, signingBytes, signature);
        }
    }

    private sealed class CountingMembershipVerifier : IMembershipSignatureVerifier
    {
        public int Calls { get; private set; }

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

    private sealed class SyntheticRuntimeSignatureVerifier : ISelfHostedRuntimeSignatureVerifier
    {
        public byte[] Sign(
            ReadOnlySpan<byte> signerId,
            ReadOnlySpan<byte> publicKey,
            ReadOnlySpan<byte> signingBytes) => Digest(signerId, publicKey, signingBytes);

        public bool Verify(
            ReadOnlySpan<byte> signerId,
            ReadOnlySpan<byte> publicKey,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature) => CryptographicOperations.FixedTimeEquals(
                Digest(signerId, publicKey, signingBytes), signature);

        private static byte[] Digest(
            ReadOnlySpan<byte> signerId,
            ReadOnlySpan<byte> publicKey,
            ReadOnlySpan<byte> signingBytes)
        {
            var input = new byte[signerId.Length + publicKey.Length + signingBytes.Length];
            signerId.CopyTo(input);
            publicKey.CopyTo(input.AsSpan(signerId.Length));
            signingBytes.CopyTo(input.AsSpan(signerId.Length + publicKey.Length));
            return SHA256.HashData(input);
        }
    }

    private sealed class MutatingRuntimeVerifier(
        ISelfHostedRuntimeSignatureVerifier inner,
        byte[] encoded) : ISelfHostedRuntimeSignatureVerifier
    {
        private bool mutated;

        public bool Verify(
            ReadOnlySpan<byte> signerId,
            ReadOnlySpan<byte> publicKey,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            if (!mutated)
            {
                encoded.AsSpan().Fill(0xee);
                mutated = true;
            }
            return inner.Verify(signerId, publicKey, signingBytes, signature);
        }
    }

    private sealed class CountingRuntimeVerifier : ISelfHostedRuntimeSignatureVerifier
    {
        public int Calls { get; private set; }

        public bool Verify(
            ReadOnlySpan<byte> signerId,
            ReadOnlySpan<byte> publicKey,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            Calls++;
            return false;
        }
    }
}
