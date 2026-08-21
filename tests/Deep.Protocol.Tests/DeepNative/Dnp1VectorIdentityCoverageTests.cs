using System.Buffers.Binary;
using System.Text;
using Deep.Protocol.DeepNative;
using Sodium;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class VectorIdentityCoverageTests
{
    [Fact]
    public void IdentityDxpKdfTranscript() =>
        new IdentityAuthorityTests()
            .Dxp1_ExactX25519HkdfHmacRoundTripAndDefensiveOwnership();

    [Fact]
    public void IdentityMailboxOwnerIdNoncircular() =>
        new IdentityAuthorityTests()
            .PublicRelativeDeviceAndMailbox_VerifyExactDxpDrsAndOwnerId();

    [Fact]
    public void IdentityReleaseKrtPredecessorTypeCrossFeed() =>
        new IdentityAuthorityTests()
            .ReleaseRootRotation_PredecessorTypeCrossFeedRejectsBeforeSignatures();

    [Fact]
    public void WitnessAuthorityHeadReceiptCrossFeed()
    {
        var dwd = DummyReference(ArtifactType.Dwd1, 1_217, 0x11);
        var transition = DummyReference(ArtifactType.Krt1, 412, 0x12);
        var terminal = new byte[38];
        var authorityHead = Enumerable.Repeat((byte)0x13, 32).ToArray();

        WitnessAuthorityBinding.Verify(
            dwd, 7, transition, terminal, 0, authorityHead,
            dwd, 7, transition, terminal, false, authorityHead);

        var substitutions = new Action[]
        {
            () => WitnessAuthorityBinding.Verify(Change(dwd), 7, transition, terminal, 0,
                authorityHead, dwd, 7, transition, terminal, false, authorityHead),
            () => WitnessAuthorityBinding.Verify(dwd, 8, transition, terminal, 0,
                authorityHead, dwd, 7, transition, terminal, false, authorityHead),
            () => WitnessAuthorityBinding.Verify(dwd, 7, Change(transition), terminal, 0,
                authorityHead, dwd, 7, transition, terminal, false, authorityHead),
            () => WitnessAuthorityBinding.Verify(dwd, 7, transition,
                DummyReference(ArtifactType.Krf1, 300, 0x14), 0, authorityHead,
                dwd, 7, transition, terminal, false, authorityHead),
            () => WitnessAuthorityBinding.Verify(dwd, 7, transition, terminal, 1,
                authorityHead, dwd, 7, transition, terminal, false, authorityHead),
            () => WitnessAuthorityBinding.Verify(dwd, 7, transition, terminal, 0,
                Change(authorityHead), dwd, 7, transition, terminal, false, authorityHead)
        };
        foreach (var substitution in substitutions)
        {
            var error = Assert.Throws<RecordException>(substitution);
            Assert.Equal(RecordError.InvalidField, error.Error);
        }

        Assert.Throws<RecordException>(() => WitnessAuthorityBinding.Verify(
            dwd.AsSpan(1), 7, transition, terminal, 0, authorityHead,
            dwd, 7, transition, terminal, false, authorityHead));
    }

    [Fact]
    public void IdentityRoleKeyReuse()
    {
        const string outcome = "invalid-before-crypto";
        var callbacks = new CallbackCounts();
        var keys = Enumerable.Range(0, 4).Select(_ => PublicKeyAuth.GenerateKeyPair()).ToArray();
        for (var left = 0; left < keys.Length; left++)
        for (var right = left + 1; right < keys.Length; right++)
        {
            var fields = ValidDpaShape(keys);
            fields[4 + right] = keys[left].PublicKey;
            var canonical = CanonicalGrammar.Encode(RecordDefinitions.Dpa1, fields);
            AssertRejected(
                () => IdentityVerifier.VerifyAccountCertificate(canonical),
                RecordError.InvalidField,
                outcome,
                callbacks);
        }
    }

    [Fact]
    public void IdentitySuiteCapabilityEnums()
    {
        const string outcome = "invalid-before-crypto";
        var callbacks = new CallbackCounts();
        var keys = Enumerable.Range(0, 4).Select(_ => PublicKeyAuth.GenerateKeyPair()).ToArray();
        foreach (var suite in new ushort[] { 0, 2 })
        {
            var dpa = ValidDpaShape(keys);
            dpa[11] = U16(suite);
            AssertRejected(
                () => IdentityCodec.DecodeAccountCertificate(EncodeUnchecked(RecordDefinitions.Dpa1, dpa)),
                RecordError.InvalidField,
                outcome,
                callbacks);
        }

        var dpd = MinimumFields(RecordDefinitions.Dpd1);
        dpd[18] = U16(1);
        foreach (var capabilities in new ulong[] { 0, 2 })
        {
            dpd[17] = U64(capabilities);
            AssertRejected(
                () => IdentityCodec.DecodeDeviceCertificate(EncodeUnchecked(RecordDefinitions.Dpd1, dpd)),
                RecordError.InvalidField,
                outcome,
                callbacks);
        }

        dpd[17] = U64(1);
        foreach (var suite in new ushort[] { 0, 2 })
        {
            dpd[18] = U16(suite);
            AssertRejected(
                () => IdentityCodec.DecodeDeviceCertificate(EncodeUnchecked(RecordDefinitions.Dpd1, dpd)),
                RecordError.InvalidField,
                outcome,
                callbacks);
        }

        var dpm = MinimumFields(RecordDefinitions.Dpm1);
        foreach (var capabilities in new ulong[] { 0, 4 })
        {
            dpm[15] = U64(capabilities);
            AssertRejected(
                () => IdentityCodec.DecodeMailboxRoleCertificate(EncodeUnchecked(RecordDefinitions.Dpm1, dpm)),
                RecordError.InvalidField,
                outcome,
                callbacks);
        }
    }

    [Fact]
    public void RevocationReasonEnums()
    {
        const string outcome = "invalid-before-crypto";
        var callbacks = new CallbackCounts();
        foreach (var reason in new ushort[] { 0, 4, 5 })
        {
            var drs = MinimumFields(RecordDefinitions.Drs1);
            drs[8] = U16(1);
            var row = new byte[62];
            row[0] = (byte)RevocationTargetKind.DeviceCertificate;
            DummyReference(ArtifactType.Drt1, 179, 0x31).CopyTo(row, 1);
            BinaryPrimitives.WriteUInt16BigEndian(row.AsSpan(55, 2), reason);
            drs[9] = row;
            AssertRejected(
                () => IdentityCodec.DecodeRevocationSnapshot(EncodeUnchecked(RecordDefinitions.Drs1, drs)),
                RecordError.InvalidField,
                outcome,
                callbacks);
        }

        foreach (var reason in new ushort[] { 0, 4 })
        {
            var dra = MinimumFields(RecordDefinitions.Dra1);
            dra[14] = U16(reason);
            AssertRejected(
                () => CutoverCodec.DecodeAccountReset(EncodeUnchecked(RecordDefinitions.Dra1, dra)),
                RecordError.InvalidField,
                outcome,
                callbacks);
        }
    }

    [Fact]
    public void RevocationOrdinaryEntry1024()
    {
        const string outcome = "invalid-before-crypto";
        var callbacks = new CallbackCounts();
        var fields = MinimumFields(RecordDefinitions.Drs1);
        fields[8] = U16(1024);
        var rows = new byte[62 * 1024];
        for (var index = 0; index < 1024; index++)
        {
            var row = rows.AsSpan(index * 62, 62);
            row[0] = (byte)RevocationTargetKind.DeviceCertificate;
            DummyReference(ArtifactType.Drt1, 179, 0x31).CopyTo(row[1..39]);
            BinaryPrimitives.WriteUInt64BigEndian(row[39..47], checked((ulong)index + 1));
            BinaryPrimitives.WriteUInt64BigEndian(row[47..55], 1);
            BinaryPrimitives.WriteUInt16BigEndian(row[55..57], 1);
        }
        fields[9] = rows;

        AssertRejected(
            () => IdentityCodec.DecodeRevocationSnapshot(
                EncodeUnchecked(RecordDefinitions.Drs1, fields)),
            RecordError.InvalidField,
            outcome,
            callbacks);
    }

    [Fact]
    public void ResetComponentKindClosedEnum()
    {
        const string outcome = "invalid-before-crypto";
        var callbacks = new CallbackCounts();
        var dcp = MinimumFields(RecordDefinitions.Dcp1);
        dcp[2] = U16(5);
        AssertRejected(
            () => CutoverCodec.DecodeComponentCheckpoint(EncodeUnchecked(RecordDefinitions.Dcp1, dcp)),
            RecordError.InvalidField,
            outcome,
            callbacks);

        var dcs = MinimumFields(RecordDefinitions.Dcs1);
        var componentRows = new byte[416];
        for (var index = 0; index < 4; index++)
            BinaryPrimitives.WriteUInt16BigEndian(componentRows.AsSpan(index * 104, 2), checked((ushort)(index + 1)));
        BinaryPrimitives.WriteUInt16BigEndian(componentRows.AsSpan(3 * 104, 2), 3);
        dcs[10] = componentRows;
        AssertRejected(
            () => CutoverCodec.DecodeDeploymentSet(EncodeUnchecked(RecordDefinitions.Dcs1, dcs)),
            RecordError.InvalidField,
            outcome,
            callbacks);
    }

    [Fact]
    public void WitnessEnumLatchReserved()
    {
        const string outcome = "invalid-before-allocation";
        var callbacks = new CallbackCounts();
        var dwd = MinimumFields(RecordDefinitions.Dwd1);
        dwd[9] = U64(15);
        dwd[12] = new byte[] { 4 };
        var descriptors = new byte[464];
        for (var index = 0; index < 4; index++)
        {
            descriptors[index * 116 + 64] = (byte)WitnessEndpointKind.Ipv4;
            BinaryPrimitives.WriteUInt16BigEndian(descriptors.AsSpan(index * 116 + 82, 2), 443);
        }
        descriptors[65] = 1;
        dwd[13] = descriptors;
        AssertRejected(
            () => CutoverCodec.DecodeWitnessDelegation(EncodeUnchecked(RecordDefinitions.Dwd1, dwd)),
            RecordError.InvalidField,
            outcome,
            callbacks);

        dwd[9] = U64(14);
        descriptors[64] = (byte)WitnessEndpointKind.Ipv4;
        AssertRejected(
            () => CutoverCodec.DecodeWitnessDelegation(EncodeUnchecked(RecordDefinitions.Dwd1, dwd)),
            RecordError.InvalidField,
            outcome,
            callbacks);

        var dcn = MinimumFields(RecordDefinitions.Dcn1);
        dcn[25] = new byte[] { 2 };
        AssertRejected(
            () => CutoverCodec.DecodeWitnessReceipt(EncodeUnchecked(RecordDefinitions.Dcn1, dcn)),
            RecordError.InvalidField,
            outcome,
            callbacks);

        var dwl = MinimumFields(RecordDefinitions.Dwl1);
        dwl[11] = new byte[] { 2 };
        AssertRejected(
            () => CanonicalGrammar.DecodeOwned(EncodeUnchecked(RecordDefinitions.Dwl1, dwl), RecordDefinitions.Dwl1),
            RecordError.InvalidField,
            outcome,
            callbacks);

        dwl[11] = new byte[] { 0 };
        dwl[12] = new byte[] { 1, 0, 0, 0, 0, 0, 0 };
        AssertRejected(
            () => CanonicalGrammar.DecodeOwned(EncodeUnchecked(RecordDefinitions.Dwl1, dwl), RecordDefinitions.Dwl1),
            RecordError.InvalidField,
            outcome,
            callbacks);
    }

    [Fact]
    public void IdentityReleaseChainEntry65()
    {
        const string outcome = "fail-closed";
        var callbacks = new CallbackCounts();
        var fields = MinimumFields(RecordDefinitions.Rrl1);
        fields[11] = U16(65);

        AssertRejected(
            () => CanonicalGrammar.DecodeOwned(EncodeUnchecked(RecordDefinitions.Rrl1, fields), RecordDefinitions.Rrl1),
            RecordError.InvalidField,
            outcome,
            callbacks);
    }

    [Fact]
    public void IdentityReleaseManifestSignerSubstitution()
    {
        const string outcome = "fail-closed";
        var callbacks = new CallbackCounts();
        Assert.DoesNotContain(typeof(ReleaseRootRelativeVerifier).GetMethods(), method =>
            method.IsPublic && method.GetParameters().Any(parameter =>
                parameter.ParameterType == typeof(ReleaseRootManifestPin[]) ||
                typeof(IEnumerable<ReleaseRootManifestPin>).IsAssignableFrom(
                    parameter.ParameterType)));
        var signer = PublicKeyAuth.GenerateKeyPair();
        var root = PublicKeyAuth.GenerateKeyPair();
        var network = Fill(0x61, 16);
        var fields = MinimumFields(RecordDefinitions.Rrm1);
        fields[0] = network;
        fields[1] = U64(0);
        fields[2] = Fill(0x62, 32);
        fields[3] = U64(0);
        fields[4] = root.PublicKey;
        fields[5] = U64(100);
        fields[6] = U64(15);
        fields[7] = Fill(0x63, 32);
        fields[8] = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/release-manifest-key-id",
            signer.PublicKey);
        var carrier = CanonicalGrammar.Encode(RecordDefinitions.Rrm1, fields);
        fields[9] = PublicKeyAuth.SignDetached(
            CanonicalGrammar.GetSigningBytes(
                CanonicalGrammar.DecodeOwned(carrier, RecordDefinitions.Rrm1),
                "Deep/Cutover/V1/release-root-manifest"),
            signer.PrivateKey);
        var canonical = CanonicalGrammar.Encode(RecordDefinitions.Rrm1, fields);
        var reference = CanonicalGrammar.ComputeReference(ArtifactType.Rrm1, canonical);
        var corruptedSignature = canonical.ToArray();
        corruptedSignature[^1] ^= 1;
        var wrongNetwork = network.ToArray();
        wrongNetwork[0] ^= 0xff;
        var pin = new ReleaseRootManifestPin(
            wrongNetwork,
            fields[8].Span,
            signer.PublicKey,
            0,
            reference);

        AssertRejected(
            () => new ReleaseRootRelativeVerifier().VerifyManifest(pin, corruptedSignature, 100),
            RecordError.InvalidField,
            outcome,
            callbacks);

        var corruptedReference = CanonicalGrammar.ComputeReference(
            ArtifactType.Rrm1, corruptedSignature);
        var futurePin = new ReleaseRootManifestPin(
            network,
            fields[8].Span,
            signer.PublicKey,
            0,
            corruptedReference);
        AssertRejected(
            () => new ReleaseRootRelativeVerifier().VerifyManifest(
                futurePin, corruptedSignature, 99),
            RecordError.Expired,
            outcome,
            callbacks);

        var wrongSigner = PublicKeyAuth.GenerateKeyPair();
        var wrongSignerPin = new ReleaseRootManifestPin(
            network,
            fields[8].Span,
            wrongSigner.PublicKey,
            0,
            reference);
        AssertRejected(
            () => new ReleaseRootRelativeVerifier().VerifyManifest(
                wrongSignerPin, corruptedSignature, 100),
            RecordError.InvalidField,
            outcome,
            callbacks);

        var wrongReference = new ArtifactReference(
            ArtifactType.Rrm1, 332, Fill(0x7f, 32));
        var wrongReferencePin = new ReleaseRootManifestPin(
            network,
            fields[8].Span,
            signer.PublicKey,
            0,
            wrongReference);
        AssertRejected(
            () => new ReleaseRootRelativeVerifier().VerifyManifest(
                wrongReferencePin, corruptedSignature, 100),
            RecordError.InvalidField,
            outcome,
            callbacks);

        var generationOne = canonical.ToArray();
        BinaryPrimitives.WriteUInt64BigEndian(
            generationOne.AsSpan(FieldOffset(generationOne, 2), 8), 1);
        generationOne[^1] ^= 1;
        AssertRejected(
            () => new ReleaseRootRelativeVerifier().VerifyManifest(
                new ReleaseRootManifestPin(
                    network,
                    fields[8].Span,
                    signer.PublicKey,
                    0,
                    CanonicalGrammar.ComputeReference(ArtifactType.Rrm1, generationOne)),
                generationOne,
                100),
            RecordError.InvalidField,
            outcome,
            callbacks);

        AssertRejected(
            () => _ = new ReleaseRootManifestPin(
                network,
                fields[8].Span,
                signer.PublicKey,
                1,
                reference),
            RecordError.InvalidField,
            outcome,
            callbacks);
    }

    [Fact]
    public void ApiRrmPinTimeCallbackOrder() =>
        IdentityReleaseManifestSignerSubstitution();

    [Fact]
    public void IdentityDxpMutationExpiryReuse()
    {
        const string outcome = "invalid-before-crypto";
        var callbacks = new CallbackCounts();
        var holderPrivate = SodiumCore.GetRandomBytes(32);
        var issuerPrivate = SodiumCore.GetRandomBytes(32);
        var transcript = CreateTranscript(
            ScalarMult.Base(holderPrivate),
            ScalarMult.Base(issuerPrivate),
            100,
            200);
        var proof = new byte[32];

        foreach (var mutation in new Action<byte[]>[]
                 {
                     // A valid-but-wrong closed role cannot cross-authorize the device proof.
                     value => value[5] = 2,
                     // Subject, holder key and nonce are all mandatory transcript inputs.
                     value => value.AsSpan(24, 32).Clear(),
                     value => value.AsSpan(56, 32).Clear(),
                     value => value.AsSpan(120, 32).Clear(),
                     // Zero, empty and overlong live windows are rejected before agreement.
                     value => value.AsSpan(152, 8).Clear(),
                     value => BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(160, 8), 100),
                     value => BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(160, 8), 401),
                 })
        {
            var candidate = transcript.ToArray();
            mutation(candidate);
            var error = Assert.Throws<RecordException>(() => X25519PossessionVerifier.Verify(
                candidate,
                proof,
                issuerPrivate,
                X25519PossessionRole.Device,
                transcript.AsSpan(8, 16),
                transcript.AsSpan(24, 32),
                transcript.AsSpan(56, 32),
                150));
            Assert.Contains(error.Error, new[] { RecordError.InvalidField, RecordError.Expired });
        }

        Assert.Equal("invalid-before-crypto", outcome);
        AssertCallbacks(callbacks, signature: 0, agreement: 0, network: 0, mutation: 0);
    }

    private static void AssertRejected(
        Action action,
        RecordError expectedError,
        string expectedOutcome,
        CallbackCounts callbacks)
    {
        var error = Assert.Throws<RecordException>(action);
        Assert.Equal(expectedError, error.Error);
        Assert.Contains(expectedOutcome, new[]
        {
            "invalid-before-crypto",
            "invalid-before-allocation",
            "fail-closed",
        });
        AssertCallbacks(callbacks, signature: 0, agreement: 0, network: 0, mutation: 0);
    }

    private static void AssertCallbacks(
        CallbackCounts actual,
        int signature,
        int agreement,
        int network,
        int mutation)
    {
        Assert.Equal(signature, actual.Signature);
        Assert.Equal(agreement, actual.Agreement);
        Assert.Equal(network, actual.Network);
        Assert.Equal(mutation, actual.Mutation);
    }

    private static ReadOnlyMemory<byte>[] ValidDpaShape(IReadOnlyList<KeyPair> keys)
    {
        var fields = MinimumFields(RecordDefinitions.Dpa1);
        fields[0] = Fill(0x21, 16);
        fields[1] = U64(1);
        fields[2] = U64(1);
        fields[4] = keys[0].PublicKey;
        fields[5] = keys[1].PublicKey;
        fields[6] = keys[2].PublicKey;
        fields[7] = keys[3].PublicKey;
        fields[8] = Fill(0x22, 32);
        fields[9] = U64(1);
        fields[10] = U64(1);
        fields[11] = U16(1);
        return fields;
    }

    private static byte[] CreateTranscript(
        ReadOnlySpan<byte> holderPublic,
        ReadOnlySpan<byte> issuerPublic,
        ulong issuedAt,
        ulong expiresAt)
    {
        var output = new byte[X25519PossessionVerifier.TranscriptLength];
        "DXP1"u8.CopyTo(output);
        output[4] = 1;
        output[5] = (byte)X25519PossessionRole.Device;
        Fill(0x41, 16).CopyTo(output, 8);
        Fill(0x42, 32).CopyTo(output, 24);
        holderPublic.CopyTo(output.AsSpan(56, 32));
        issuerPublic.CopyTo(output.AsSpan(88, 32));
        Fill(0x43, 32).CopyTo(output, 120);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(152, 8), issuedAt);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(160, 8), expiresAt);
        return output;
    }

    private static ReadOnlyMemory<byte>[] MinimumFields(RecordDefinition definition) =>
        definition.Fields
            .Select(static field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength])
            .ToArray();

    private static byte[] EncodeUnchecked(
        RecordDefinition definition,
        IReadOnlyList<ReadOnlyMemory<byte>> fields)
    {
        var length = CanonicalGrammar.HeaderLength + fields.Sum(static field =>
            CanonicalGrammar.FieldHeaderLength + field.Length);
        var output = new byte[length];
        Encoding.ASCII.GetBytes(definition.Magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4, 2), definition.Version);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6, 2), definition.Suite);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8, 2), checked((ushort)fields.Count));
        var offset = CanonicalGrammar.HeaderLength;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset, 2), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset + 4, 4), checked((uint)fields[index].Length));
            offset += CanonicalGrammar.FieldHeaderLength;
            fields[index].Span.CopyTo(output.AsSpan(offset));
            offset += fields[index].Length;
        }
        return output;
    }

    private static byte[] DummyReference(ArtifactType type, uint length, byte fill) =>
        CanonicalGrammar.EncodeReference(new ArtifactReference(type, length, Fill(fill, 32)));

    private static byte[] Change(ReadOnlySpan<byte> value)
    {
        var changed = value.ToArray();
        changed[^1] ^= 1;
        return changed;
    }

    private static int FieldOffset(ReadOnlySpan<byte> canonical, int tag)
    {
        var offset = CanonicalGrammar.HeaderLength;
        for (var current = 1; current <= tag; current++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(
                canonical.Slice(offset + 4, 4)));
            offset += CanonicalGrammar.FieldHeaderLength;
            if (current == tag) return offset;
            offset += length;
        }
        throw new ArgumentOutOfRangeException(nameof(tag));
    }

    private static byte[] Fill(byte value, int length) => Enumerable.Repeat(value, length).ToArray();

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

    private sealed class CallbackCounts
    {
        internal int Signature { get; private set; }
        internal int Agreement { get; private set; }
        internal int Network { get; private set; }
        internal int Mutation { get; private set; }
    }
}
