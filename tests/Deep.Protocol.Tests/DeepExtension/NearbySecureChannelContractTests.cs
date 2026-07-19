using System.Reflection;
using System.Runtime.InteropServices;
using Deep.Protocol.DeepExtension.NearbyHandshakes;
using Deep.Protocol.DeepExtension.OpaqueBundles;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class NearbySecureChannelContractTests
{
    private const string ContractNamespace =
        "Deep.Protocol.DeepExtension.NearbySecureChannels";

    private static readonly Assembly ProtocolAssembly = typeof(NearbyHandshakeProtocol).Assembly;

    [Fact]
    public void PublicSurface_IsTypedOpaqueAndFreshOnly()
    {
        var ake = RequiredType("INearbyFreshAke");
        var pending = RequiredType("INearbyPendingSession");
        var channel = RequiredType("INearbySecureSession");
        var replay = RequiredType("INearbyReplayCommitter");

        Assert.True(ake.IsInterface);
        Assert.True(pending.IsInterface);
        Assert.True(channel.IsInterface);
        Assert.True(replay.IsInterface);

        Assert.Equal(
            ["AcceptInitiator", "AcceptResponder", "BeginInitiator"],
            ake.GetMethods().Select(static method => method.Name).Order().ToArray());
        Assert.Contains(pending.GetMethods(), method =>
            method.Name == "Activate" && method.ReturnType == channel);
        Assert.Contains(channel.GetMethods(), method => method.Name == "Seal");
        Assert.Contains(channel.GetMethods(), method => method.Name == "Open");

        var profile = RequiredType("NearbySecureChannelProfileId");
        Assert.True(profile.IsEnum);
        Assert.Equal(
            ["UnassignedPendingExternalCryptoReview"],
            Enum.GetNames(profile));

        var context = RequiredType("NearbyAkeContext");
        Assert.Contains(context.GetProperties(), property =>
            property.Name == "Binding" &&
            property.PropertyType == typeof(NearbyHandshakeBinding));
        Assert.Contains(context.GetProperties(), property =>
            property.Name == "LocalKeyHandle" &&
            property.PropertyType == RequiredType("NearbyLocalDeviceKeyHandle"));
        Assert.Contains(context.GetProperties(), property =>
            property.Name == "ExpectedPeerCredential" &&
            property.PropertyType == RequiredType("NearbyDeviceCredential"));
    }

    [Fact]
    public void IdentifiersAndDigests_RejectInvalidValuesCopyBuffersAndRedact()
    {
        AssertOpaqueValue("NearbyAccountIdentity", 1, 512);
        AssertOpaqueValue("NearbyDeviceKeyId", 16, 64);
        AssertOpaqueValue("NearbyTranscriptDigest", 32, 64);
    }

    [Fact]
    public void Context_RejectsResumptionAndInvalidCredentialState()
    {
        var active = Credential(
            epoch: 7,
            validFrom: DateTimeOffset.UnixEpoch,
            validUntil: DateTimeOffset.UnixEpoch.AddDays(2),
            status: "Active");

        _ = CreateContext(
            Binding(NearbyHandshakeMode.Fresh, resumeCounter: 0),
            active,
            rosterEpoch: 7,
            validationTime: DateTimeOffset.UnixEpoch.AddDays(1));

        AssertContractError(
            "ResumptionNotSupported",
            () => CreateContext(
                Binding(NearbyHandshakeMode.Resumption, resumeCounter: 1),
                active,
                rosterEpoch: 7,
                validationTime: DateTimeOffset.UnixEpoch.AddDays(1)));

        foreach (var scenario in new[]
                 {
                     (Epoch: 7UL, From: DateTimeOffset.UnixEpoch.AddDays(2),
                         Until: DateTimeOffset.UnixEpoch.AddDays(3), Status: "Active",
                         Error: "CredentialNotYetValid"),
                     (Epoch: 7UL, From: DateTimeOffset.UnixEpoch,
                         Until: DateTimeOffset.UnixEpoch.AddHours(1), Status: "Active",
                         Error: "CredentialExpired"),
                     (Epoch: 7UL, From: DateTimeOffset.UnixEpoch,
                         Until: DateTimeOffset.UnixEpoch.AddDays(3), Status: "Revoked",
                         Error: "CredentialRevoked"),
                     (Epoch: 6UL, From: DateTimeOffset.UnixEpoch,
                         Until: DateTimeOffset.UnixEpoch.AddDays(3), Status: "Active",
                         Error: "RosterRollback")
                 })
        {
            var credential = Credential(
                scenario.Epoch,
                scenario.From,
                scenario.Until,
                scenario.Status);
            AssertContractError(
                scenario.Error,
                () => CreateContext(
                    Binding(NearbyHandshakeMode.Fresh, 0),
                    credential,
                    rosterEpoch: 7,
                    validationTime: DateTimeOffset.UnixEpoch.AddDays(1)));
        }
    }

    [Fact]
    public void HandshakeFlights_AreBoundedAndHaveNoApplicationPayloadSurface()
    {
        var payloadType = RequiredType("NearbyHandshakePayload");
        var payloadPurpose = RequiredType("NearbyHandshakePayloadPurpose");
        Assert.Equal(
            ["AuthenticatedKeyExchangeOnly"],
            Enum.GetNames(payloadPurpose));

        Assert.ThrowsAny<Exception>(() => Create(payloadType, new byte[15].AsMemory()));
        Assert.ThrowsAny<Exception>(() => Create(payloadType, new byte[1025].AsMemory()));

        var input = Enumerable.Range(0, 16).Select(static value => (byte)value).ToArray();
        var payload = Create(payloadType, input.AsMemory());
        input[0] ^= 0xff;
        Assert.Equal(0, ReadBytes(payload, "Bytes")[0]);
        Assert.Equal(
            "AuthenticatedKeyExchangeOnly",
            ReadProperty(payload, "Purpose").ToString());
        Assert.Contains("redacted", payload.ToString(), StringComparison.OrdinalIgnoreCase);

        foreach (var typeName in new[] { "NearbyInitiatorFlight", "NearbyResponderFlight" })
        {
            var type = RequiredType(typeName);
            var publicNames = type.GetMembers(BindingFlags.Instance | BindingFlags.Public)
                .Select(static member => member.Name)
                .Concat(type.GetConstructors()
                    .SelectMany(static constructor => constructor.GetParameters())
                    .Select(static parameter => parameter.Name ?? string.Empty));
            Assert.DoesNotContain(publicNames, name =>
                name.Contains("application", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("bundle", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("plaintext", StringComparison.OrdinalIgnoreCase));
        }
    }

    [Fact]
    public void ReplayAcceptance_BindsDurableFreshScopeAndRejectsCollisions()
    {
        var claimType = RequiredType("NearbyFreshReplayClaim");
        var acceptanceType = RequiredType("NearbyReplayAcceptance");
        var classificationType = RequiredType("NearbyReplayClaimClassification");
        Assert.Contains("AcceptedFresh", Enum.GetNames(classificationType));
        Assert.Contains("CollisionDifferentTranscript", Enum.GetNames(classificationType));
        Assert.DoesNotContain(Enum.GetNames(classificationType), name =>
            name.Contains("Resumption", StringComparison.OrdinalIgnoreCase));

        var local = Opaque("NearbyDeviceKeyId", 0x20, 32);
        var peer = Opaque("NearbyDeviceKeyId", 0x60, 32);
        var attemptBytes = Range(0xa0, 16);
        var attempt = new TransportAttemptId(attemptBytes);
        var digest = Opaque("NearbyTranscriptDigest", 0xc0, 32);
        var claim = Create(claimType, local, peer, attempt, digest, 9UL);

        attemptBytes[0] ^= 0xff;
        var storedAttempt = ReadProperty(claim, "TransportAttemptId");
        Assert.Equal(0xa0, ReadBytes(storedAttempt, "Bytes")[0]);
        Assert.Equal(9UL, ReadProperty(claim, "RosterEpoch"));

        var accepted = Enum.Parse(classificationType, "AcceptedFresh");
        var collision = Enum.Parse(classificationType, "CollisionDifferentTranscript");
        var acceptance = CreateNonPublic(
            acceptanceType,
            local,
            peer,
            attempt,
            digest,
            9UL,
            accepted);
        Assert.Equal("AcceptedFresh", ReadProperty(acceptance, "Classification").ToString());
        Assert.Contains("redacted", acceptance.ToString(), StringComparison.OrdinalIgnoreCase);

        Assert.ThrowsAny<Exception>(() => CreateNonPublic(
            acceptanceType,
            local,
            peer,
            attempt,
            digest,
            9UL,
            collision));
    }

    [Fact]
    public void OpenedRecords_AreBoundedDefensivelyCopiedAndDirectional()
    {
        var recordType = RequiredType("NearbyOpenedRecord");
        var kindType = RequiredType("NearbyRecordKind");
        Assert.Equal(["Control", "OpaqueBundle"], Enum.GetNames(kindType));

        var kind = Enum.Parse(kindType, "OpaqueBundle");
        Assert.ThrowsAny<Exception>(() => Create(recordType, kind, 0UL, ReadOnlyMemory<byte>.Empty));

        var bytes = Range(0x10, 32);
        var record = Create(recordType, kind, 4UL, bytes.AsMemory());
        bytes[0] ^= 0xff;
        Assert.Equal(0x10, ReadBytes(record, "Plaintext")[0]);
        Assert.Equal(4UL, ReadProperty(record, "Counter"));
    }

    [Fact]
    public void ContractAssembly_HasNoRawKeySurfaceOrProductionImplementation()
    {
        var contractTypes = ProtocolAssembly.GetTypes()
            .Where(type => type.Namespace == ContractNamespace)
            .ToArray();
        Assert.NotEmpty(contractTypes);

        var forbiddenCryptoNames = new[]
        {
            "Noise", "Hmac", "Aes", "ChaCha", "Authenticator", "Prf"
        };
        Assert.DoesNotContain(contractTypes, type =>
            forbiddenCryptoNames.Any(name =>
                type.Name.Contains(name, StringComparison.OrdinalIgnoreCase)));

        var forbiddenKeySurface = new[]
        {
            "PrivateKey", "SecretKey", "StaticKey", "EphemeralKey",
            "TrafficKey", "SessionKey", "RawKey"
        };
        foreach (var type in contractTypes)
        {
            var publicSurface = type.GetMembers(BindingFlags.Instance | BindingFlags.Public)
                .Select(static member => member.Name)
                .Concat(type.GetMethods().Select(static method => method.ReturnType.Name))
                .Concat(type.GetMethods().SelectMany(static method => method.GetParameters())
                    .Select(static parameter => parameter.ParameterType.Name));
            Assert.DoesNotContain(publicSurface, name =>
                forbiddenKeySurface.Any(forbidden =>
                    name.Contains(forbidden, StringComparison.OrdinalIgnoreCase)));
        }

        foreach (var interfaceName in new[]
                 {
                     "INearbyFreshAke",
                     "INearbyPendingSession",
                     "INearbySecureSession",
                     "INearbyReplayCommitter"
                 })
        {
            var contract = RequiredType(interfaceName);
            Assert.DoesNotContain(contractTypes, type =>
                type is { IsInterface: false, IsAbstract: false } &&
                contract.IsAssignableFrom(type));
        }
    }

    private static object CreateContext(
        NearbyHandshakeBinding binding,
        object expectedPeerCredential,
        ulong rosterEpoch,
        DateTimeOffset validationTime)
    {
        var profileType = RequiredType("NearbySecureChannelProfileId");
        var profile = Enum.Parse(profileType, "UnassignedPendingExternalCryptoReview");
        return Create(
            RequiredType("NearbyAkeContext"),
            profile,
            binding,
            Opaque("NearbyAccountIdentity", 0x05, 33),
            Opaque("NearbyDeviceKeyId", 0x20, 32),
            Activator.CreateInstance(RequiredType("NearbyLocalDeviceKeyHandle"), nonPublic: true)!,
            expectedPeerCredential,
            rosterEpoch,
            validationTime);
    }

    private static object Credential(
        ulong epoch,
        DateTimeOffset validFrom,
        DateTimeOffset validUntil,
        string status)
    {
        var statusType = RequiredType("NearbyDeviceCredentialStatus");
        return Create(
            RequiredType("NearbyDeviceCredential"),
            Opaque("NearbyAccountIdentity", 0x45, 33),
            Opaque("NearbyDeviceKeyId", 0x60, 32),
            epoch,
            validFrom,
            validUntil,
            Enum.Parse(statusType, status));
    }

    private static NearbyHandshakeBinding Binding(
        NearbyHandshakeMode mode,
        ulong resumeCounter) =>
        new()
        {
            BundleVersion = 1,
            Period = 100,
            TransportAttemptId = new TransportAttemptId(Range(0x80, 16)),
            SimultaneousOpenToken = Range(0x90, 16),
            Mode = mode,
            ResumeCounter = resumeCounter
        };

    private static void AssertOpaqueValue(string typeName, int minimum, int maximum)
    {
        var type = RequiredType(typeName);
        Assert.ThrowsAny<Exception>(() => Create(type, ReadOnlyMemory<byte>.Empty));
        Assert.ThrowsAny<Exception>(() => Create(type, new byte[minimum - 1].AsMemory()));
        Assert.ThrowsAny<Exception>(() => Create(type, new byte[maximum + 1].AsMemory()));
        Assert.ThrowsAny<Exception>(() => Create(type, new byte[minimum].AsMemory()));

        var input = Range(1, minimum);
        var instance = Create(type, input.AsMemory());
        input[0] ^= 0xff;
        Assert.Equal(1, ReadBytes(instance, "Bytes")[0]);

        var exposed = ReadProperty(instance, "Bytes");
        Assert.True(MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)exposed, out var segment));
        segment.Array![segment.Offset] ^= 0xff;
        Assert.Equal(1, ReadBytes(instance, "Bytes")[0]);
        Assert.Contains("redacted", instance.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    private static void AssertContractError(string error, Action action)
    {
        var exception = Assert.ThrowsAny<Exception>(action);
        var current = exception;
        while (current is TargetInvocationException { InnerException: not null })
        {
            current = current.InnerException;
        }

        Assert.Equal("NearbySecureChannelException", current.GetType().Name);
        Assert.Equal(error, ReadProperty(current, "Error").ToString());
    }

    private static object Opaque(string typeName, int start, int length) =>
        Create(RequiredType(typeName), Range(start, length).AsMemory());

    private static Type RequiredType(string name) =>
        ProtocolAssembly.GetType($"{ContractNamespace}.{name}", throwOnError: true)!;

    private static object Create(Type type, params object?[] arguments) =>
        Activator.CreateInstance(type, arguments)
        ?? throw new InvalidOperationException($"Could not create {type.FullName}.");

    private static object CreateNonPublic(Type type, params object?[] arguments) =>
        type.GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic)
            .Single(constructor => constructor.GetParameters().Length == arguments.Length)
            .Invoke(arguments);

    private static object ReadProperty(object instance, string name) =>
        instance.GetType().GetProperty(name)!.GetValue(instance)!;

    private static byte[] ReadBytes(object instance, string propertyName) =>
        ((ReadOnlyMemory<byte>)ReadProperty(instance, propertyName)).ToArray();

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => (byte)value).ToArray();
}
