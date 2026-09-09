using System.Reflection;
using System.Buffers.Binary;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity.DeviceV1;

namespace Deep.Protocol.Tests.Identity.DeviceV1;

public sealed class DeviceV1CapabilityBoundaryTests
{
    [Theory]
    [InlineData(typeof(VerifiedDeviceRevocationSuccessor))]
    [InlineData(typeof(VerifiedDeviceControlSuccessor))]
    [InlineData(typeof(VerifiedAccountDirectoryDeviceSuccessor))]
    [InlineData(typeof(VerifiedDeviceHistoryTransferAuthorization))]
    [InlineData(typeof(VerifiedDeviceBackupManifest))]
    [InlineData(typeof(VerifiedDeviceBackupAuthorization))]
    public void SealedCapabilities_HaveNoPublicConstructor(Type capability)
    {
        Assert.True(capability.IsSealed);
        Assert.Empty(capability.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
    }

    [Fact]
    public void RevocationCapability_HasOnlyProtocolVerifierAcquisition()
    {
        var assembly = typeof(VerifiedDeviceRevocationSuccessor).Assembly;
        var producers = assembly.GetExportedTypes()
            .SelectMany(static type => type.GetMethods(BindingFlags.Public | BindingFlags.Static))
            .Where(static method => method.ReturnType == typeof(VerifiedDeviceRevocationSuccessor))
            .ToArray();
        var producer = Assert.Single(producers);
        Assert.Equal(typeof(DeviceRevocationSuccessorVerifier), producer.DeclaringType);
        Assert.Equal(nameof(DeviceRevocationSuccessorVerifier.Verify), producer.Name);
        Assert.DoesNotContain(producer.GetParameters(), static parameter =>
            parameter.ParameterType == typeof(byte[]) || parameter.ParameterType == typeof(bool)
            || parameter.ParameterType == typeof(ReadOnlyMemory<byte>));
    }

    [Fact]
    public void HistoryAuthority_RequiresVerifiedProtocolObjects_NotBoolOrBareHash()
    {
        var methods = typeof(DeviceHistoryAuthorizationVerifier)
            .GetMethods(BindingFlags.Public | BindingFlags.Static);
        Assert.Equal(2, methods.Length);
        Assert.DoesNotContain(methods.SelectMany(static method => method.GetParameters()),
            static parameter => parameter.ParameterType == typeof(bool)
                || parameter.ParameterType == typeof(byte[])
                || parameter.ParameterType == typeof(ReadOnlyMemory<byte>));
        Assert.Contains(methods, static method =>
            method.ReturnType == typeof(VerifiedDeviceHistoryTransferAuthorization));
        Assert.Contains(methods, static method =>
            method.ReturnType == typeof(VerifiedDeviceBackupAuthorization));
    }

    [Fact]
    public void CapabilityPublicData_IsDefensivelyCopied()
    {
        var account = Bytes(0x10); var device = Bytes(0x20); var manifestHash = Bytes(0x30);
        var manifest = new VerifiedDeviceBackupManifest(account, 7, device, manifestHash);
        var authorization = VerifiedDeviceBackupAuthorization.Create(manifest);
        var first = authorization.ManifestHash.ToArray();
        first[0] ^= 0xFF;
        Assert.Equal(manifestHash, authorization.ManifestHash.ToArray());
        Assert.Equal(7UL, authorization.AccountGeneration);
    }

    [Fact]
    public void ProductionSurface_HasNoSharedAssemblyFriendAccess()
    {
        var friendNames = typeof(VerifiedDeviceRevocationSuccessor).Assembly
            .GetCustomAttributes<System.Runtime.CompilerServices.InternalsVisibleToAttribute>()
            .Select(static attribute => attribute.AssemblyName)
            .Where(static name => name.StartsWith("Deep.Client.Shared", StringComparison.Ordinal))
            .ToArray();
        Assert.Empty(friendNames);
    }

    private static byte[] Bytes(byte marker) =>
        Enumerable.Range(0, 32).Select(index => unchecked((byte)(marker + index))).ToArray();
}

public sealed class DeviceRevocationSuccessorVerifierTests
{
    [Fact]
    public void Verify_BindsExactAppendOneDrsAndRevokedDpd()
    {
        var fixture = Fixture.Create();
        var verified = DeviceRevocationSuccessorVerifier.Verify(
            fixture.Prior, fixture.Successor, fixture.Device);
        Assert.Equal(1UL, verified.PriorDrsRevision);
        Assert.Equal(2UL, verified.SuccessorDrsRevision);
        Assert.Equal(fixture.Device.Certificate.DeviceId.ToArray(), verified.RevokedDeviceId.ToArray());
        Assert.Equal(fixture.Device.Certificate.CanonicalHash.ToArray(),
            verified.RevokedDpdReference.CanonicalHash.ToArray());
    }

    [Fact]
    public void Verify_RejectsSkippedRevisionAndMissingCatalogMembership()
    {
        var fixture = Fixture.Create(successorRevision: 3);
        Assert.Throws<RecordException>(() => DeviceRevocationSuccessorVerifier.Verify(
            fixture.Prior, fixture.Successor, fixture.Device));
        var missing = Fixture.Create(includeCatalog: false);
        Assert.Throws<RecordException>(() => DeviceRevocationSuccessorVerifier.Verify(
            missing.Prior, missing.Successor, missing.Device));
    }

    private sealed record Fixture(VerifiedRevocationState Prior,
        VerifiedRevocationState Successor, VerifiedDevice Device)
    {
        internal static Fixture Create(ulong successorRevision = 2, bool includeCatalog = true)
        {
            var network = Fill(0x11, 16); var accountId = Fill(0x22, 32); var deviceId = Fill(0x33, 32);
            var dpa = Minimum(RecordDefinitions.Dpa1);
            dpa[0] = network; dpa[1] = U64(1); dpa[2] = U64(1);
            dpa[4] = Fill(0x41, 32); dpa[5] = Fill(0x42, 32); dpa[6] = Fill(0x43, 32);
            dpa[7] = Fill(0x44, 32); dpa[8] = Fill(0x45, 32); dpa[9] = U64(100);
            dpa[10] = U64(1); dpa[11] = U16(1);
            var accountCertificate = IdentityCodec.DecodeAccountCertificate(
                CanonicalGrammar.Encode(RecordDefinitions.Dpa1, dpa));
            var account = new VerifiedAccount(accountCertificate, accountId);

            var priorSnapshot = Snapshot(network, accountId, 1, null, null);
            var prior = new VerifiedRevocationState(account, priorSnapshot, new RevocationCatalog([]));
            var dpd = Minimum(RecordDefinitions.Dpd1);
            dpd[0] = network; dpd[1] = accountId; dpd[2] = U64(1); dpd[3] = deviceId;
            dpd[4] = U64(1); dpd[5] = Fill(0x51, 32); dpd[6] = Fill(0x52, 32);
            dpd[7] = Fill(0x53, 32); dpd[8] = U64(1); dpd[10] = Fill(0x54, 32);
            dpd[11] = U64(1); dpd[13] = U64(0); dpd[14] = priorSnapshot.CurrentHead.ToArray();
            dpd[15] = U64(100); dpd[16] = U64(1_000); dpd[17] = U64(1); dpd[18] = U16(1);
            dpd[20] = Fill(0x55, 32);
            var certificate = IdentityCodec.DecodeDeviceCertificate(
                CanonicalGrammar.Encode(RecordDefinitions.Dpd1, dpd));
            var device = new VerifiedDevice(certificate, prior,
                new X25519Possession(X25519PossessionRole.Device, dpd[20].Span));

            var targetFields = Minimum(RecordDefinitions.Drt1);
            targetFields[0] = accountId;
            targetFields[1] = new[] { (byte)RevocationTargetKind.DeviceCertificate };
            targetFields[2] = certificate.RevocationHandle;
            targetFields[3] = U64(certificate.DeviceGeneration);
            targetFields[4] = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                ArtifactType.Dpd1, certificate.CanonicalBytes.Span));
            targetFields[5] = U64(certificate.ExpiresAtUnixSeconds);
            var targetCanonical = CanonicalGrammar.Encode(RecordDefinitions.Drt1, targetFields);
            var target = new RevocationTarget(CanonicalGrammar.DecodeOwned(targetCanonical, RecordDefinitions.Drt1));
            var row = new byte[62]; row[0] = (byte)RevocationTargetKind.DeviceCertificate;
            CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                ArtifactType.Drt1, targetCanonical)).CopyTo(row, 1);
            BinaryPrimitives.WriteUInt64BigEndian(row.AsSpan(39), 1);
            BinaryPrimitives.WriteUInt64BigEndian(row.AsSpan(47), 101);
            BinaryPrimitives.WriteUInt16BigEndian(row.AsSpan(55), (ushort)RevocationReason.DeviceLost);
            var successorSnapshot = Snapshot(network, accountId, successorRevision, row, priorSnapshot.CurrentHead.ToArray());
            var catalog = includeCatalog
                ? new RevocationCatalog([new RevocationCatalogEntry(target, 101,
                    RevocationReason.DeviceLost, certificate.CanonicalBytes.Span, default)])
                : new RevocationCatalog([]);
            return new(prior, new VerifiedRevocationState(account, successorSnapshot, catalog), device);
        }

        private static RevocationSnapshot Snapshot(byte[] network, byte[] account, ulong revision,
            byte[]? row, byte[]? predecessorHead)
        {
            var fields = Minimum(RecordDefinitions.Drs1);
            fields[0] = network; fields[1] = account; fields[2] = U64(1); fields[3] = U64(revision);
            fields[4] = U64(100 + revision); fields[5] = U64(0); fields[7] = Fill(0x77, 32);
            if (row is not null)
            {
                fields[8] = U16(1); fields[9] = row;
                var payload = new byte[158]; network.CopyTo(payload, 0); account.CopyTo(payload, 16);
                U64(1).CopyTo(payload, 48); (predecessorHead ?? new byte[32]).CopyTo(payload, 56);
                row.CopyTo(payload, 96);
                fields[10] = CanonicalGrammar.Sha256Domain(
                    "Deep/IdentityAuth/V1/revocation-entry-head", payload);
            }
            return IdentityCodec.DecodeRevocationSnapshot(
                CanonicalGrammar.Encode(RecordDefinitions.Drs1, fields));
        }
        private static ReadOnlyMemory<byte>[] Minimum(RecordDefinition definition) =>
            definition.Fields.Select(static field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();
        private static byte[] Fill(byte marker, int length) =>
            Enumerable.Repeat(marker, length).ToArray();
        private static byte[] U64(ulong value)
        { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
        private static byte[] U16(ushort value)
        { var bytes = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); return bytes; }
    }
}
