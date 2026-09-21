using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepNative;
using Deep.Protocol.ContactV1;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace Deep.Protocol.ApplicationCore;

/// <summary>
/// A protocol-owned identity closure. Its inputs are themselves nonforgeable
/// capabilities emitted by the DNP1 verifier; raw DPA1/DRS1/DPD1 bytes cannot
/// be promoted through this API.
/// </summary>
public sealed class VerifiedApplicationIdentityClosure
{
    private readonly Dictionary<string, VerifiedDevice> devices;

    internal VerifiedApplicationIdentityClosure(
        VerifiedAccount account,
        VerifiedRevocationState revocations,
        IReadOnlyList<VerifiedDevice> activeDevices)
    {
        Account = account;
        Revocations = revocations;
        devices = new Dictionary<string, VerifiedDevice>(StringComparer.Ordinal);
        foreach (var device in activeDevices)
            devices.Add(Convert.ToHexString(device.Certificate.DeviceId.Span), device);
    }

    public VerifiedAccount Account { get; }
    public VerifiedRevocationState Revocations { get; }
    public IReadOnlyList<VerifiedDevice> ActiveDevices => devices.Values.ToArray();

    internal bool TryGetDevice(ReadOnlySpan<byte> deviceId, out VerifiedDevice? device) =>
        devices.TryGetValue(Convert.ToHexString(deviceId), out device);
}

public sealed class VerifiedDab1
{
    internal VerifiedDab1(ParsedDab1 record, ParsedDid1 deepId, VerifiedApplicationIdentityClosure identity)
    {
        Record = record;
        DeepId = deepId;
        Identity = identity;
    }

    public ParsedDab1 Record { get; }
    public ParsedDid1 DeepId { get; }
    public VerifiedApplicationIdentityClosure Identity { get; }
}

public sealed class VerifiedDmd1
{
    internal VerifiedDmd1(ParsedDmd1 record, VerifiedApplicationIdentityClosure identity)
    {
        Record = record;
        Identity = identity;
    }

    public ParsedDmd1 Record { get; }
    public VerifiedApplicationIdentityClosure Identity { get; }
}

public sealed class VerifiedDca1
{
    internal VerifiedDca1(ParsedDca1 record, VerifiedDab1 binding, VerifiedDmd1 directory)
    {
        Record = record;
        Binding = binding;
        Directory = directory;
    }

    public ParsedDca1 Record { get; }
    public VerifiedDab1 Binding { get; }
    public VerifiedDmd1 Directory { get; }
}

/// <summary>
/// A cryptographically verified DCA1 that is authoritative at one caller-
/// supplied trusted instant. This capability is deliberately distinct from
/// <see cref="VerifiedDca1"/>, whose signatures and identity closure remain
/// valid evidence after its publication window closes.
/// </summary>
public sealed class CurrentlyAuthoritativeDca1
{
    internal CurrentlyAuthoritativeDca1(VerifiedDca1 verified, ulong trustedUnixSeconds)
    {
        Verified = verified;
        TrustedUnixSeconds = trustedUnixSeconds;
    }

    public VerifiedDca1 Verified { get; }
    public ulong TrustedUnixSeconds { get; }
}

public enum ApplicationLineageDisposition
{
    AcceptedGenesis = 1,
    AcceptedSuccessor = 2,
    ExactReplay = 3,
    ForkLatched = 4,
}

public sealed class Dab1LineageState
{
    internal Dab1LineageState(VerifiedDab1 head, bool forkLatched)
    {
        Head = head;
        ForkLatched = forkLatched;
    }

    public VerifiedDab1 Head { get; }
    public bool ForkLatched { get; }
}

public sealed class Dmd1LineageState
{
    internal Dmd1LineageState(VerifiedDmd1 head, bool forkLatched)
    {
        Head = head;
        ForkLatched = forkLatched;
    }

    public VerifiedDmd1 Head { get; }
    public bool ForkLatched { get; }
}

public sealed class Dab1LineageTransitionPlan
{
    internal Dab1LineageTransitionPlan(
        Dab1LineageState previous,
        Dab1LineageState next,
        ApplicationLineageDisposition disposition)
    {
        Previous = previous;
        Next = next;
        Disposition = disposition;
    }

    public Dab1LineageState Previous { get; }
    public Dab1LineageState Next { get; }
    public ApplicationLineageDisposition Disposition { get; }
}

public sealed class Dmd1LineageTransitionPlan
{
    internal Dmd1LineageTransitionPlan(
        Dmd1LineageState previous,
        Dmd1LineageState next,
        ApplicationLineageDisposition disposition)
    {
        Previous = previous;
        Next = next;
        Disposition = disposition;
    }

    public Dmd1LineageState Previous { get; }
    public Dmd1LineageState Next { get; }
    public ApplicationLineageDisposition Disposition { get; }
}

public sealed class VerifiedDmc2
{
    internal VerifiedDmc2(ParsedDmc2 record, Dmc2Payload payload, VerifiedDpe2Envelope envelope)
    {
        Record = record;
        Payload = payload;
        AuthenticatedEnvelope = envelope;
    }

    public ParsedDmc2 Record { get; }
    public Dmc2Payload Payload { get; }
    public VerifiedDpe2Envelope AuthenticatedEnvelope { get; }
}

public static class ApplicationCoreVerifier
{
    /// <summary>
    /// Promotes only public DNP1 verifier outputs into the application identity
    /// boundary. Each device must originate from the exact same identity result;
    /// caller-created DPA1/DRS1/DPD1 bytes cannot satisfy this overload.
    /// </summary>
    public static VerifiedApplicationIdentityClosure CreateIdentityClosure(
        VerifiedIdentityRelative identity,
        IReadOnlyList<VerifiedDeviceRelative> activeDevices)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(activeDevices);
        var verified = new VerifiedDevice[activeDevices.Count];
        for (var index = 0; index < activeDevices.Count; index++)
        {
            var device = activeDevices[index] ??
                throw new ArgumentException("A null verified device is not allowed.", nameof(activeDevices));
            if (!ReferenceEquals(device.Identity, identity))
                Reject("A verified device belongs to a different DPA1/DRS1 identity result.");
            verified[index] = device.Device;
        }
        return CreateIdentityClosure(identity.Account, identity.Revocations, verified);
    }

    public static VerifiedApplicationIdentityClosure CreateIdentityClosure(
        VerifiedAccount account,
        VerifiedRevocationState revocations,
        IReadOnlyList<VerifiedDevice> activeDevices)
    {
        ArgumentNullException.ThrowIfNull(account);
        ArgumentNullException.ThrowIfNull(revocations);
        ArgumentNullException.ThrowIfNull(activeDevices);
        if (!SameAccount(account, revocations.Account))
            Reject("DRS1 is not verified for the exact DPA1 account.");

        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var device in activeDevices)
        {
            ArgumentNullException.ThrowIfNull(device);
            if (!SameAccount(account, device.Revocations.Account) ||
                !SameArtifact(revocations.Snapshot, device.Revocations.Snapshot) ||
                !device.Certificate.NetworkId.Span.SequenceEqual(account.Certificate.NetworkId.Span) ||
                !device.Certificate.AccountHash.Span.SequenceEqual(account.DeepAccountIdHash.Span) ||
                device.Certificate.AccountGeneration != account.Certificate.AccountGeneration)
                Reject("A DPD1 is not verified against the exact DPA1/DRS1 closure.");
            if (!ids.Add(Convert.ToHexString(device.Certificate.DeviceId.Span)))
                Reject("The verified identity closure contains a duplicate device ID.");
        }

        return new VerifiedApplicationIdentityClosure(account, revocations, activeDevices);
    }

    public static VerifiedDab1 VerifyDab1(
        ParsedDab1 parsed,
        ParsedDid1 deepId,
        VerifiedApplicationIdentityClosure identity,
        ushort deploymentProfileId)
    {
        ArgumentNullException.ThrowIfNull(parsed);
        ArgumentNullException.ThrowIfNull(deepId);
        ArgumentNullException.ThrowIfNull(identity);
        var account = identity.Account;
        Span<byte> realmInput = stackalloc byte[18];
        account.Certificate.NetworkId.Span.CopyTo(realmInput);
        BinaryPrimitives.WriteUInt16BigEndian(realmInput[16..], deploymentProfileId);
        var expectedRealm = ApplicationCoreFormat.Sha256Domain(
            "Deep/Application/V1/address-binding-realm", realmInput);

        if (!parsed.ExactDid1Hash.Span.SequenceEqual(deepId.RecordHash.Span) ||
            !parsed.IdentityRealmId.Span.SequenceEqual(expectedRealm) ||
            !parsed.DeepAccountId.Span.SequenceEqual(account.DeepAccountIdHash.Span) ||
            parsed.AccountGeneration != account.Certificate.AccountGeneration ||
            !References(parsed.Dpa1Reference, account.Certificate))
            Reject("DAB1 does not close over the exact DID1/DPA1 identity realm.");
        VerifySignature(parsed.AddressSignature.Span, parsed.AddressSignatureInput.Span,
            deepId.AddressPublicKey.Span, "DAB1 address signature");
        VerifySignature(parsed.AccountSignature.Span, parsed.AccountSignatureInput.Span,
            account.Certificate.AccountEd25519PublicKey.Span, "DAB1 account signature");
        return new VerifiedDab1(parsed, deepId, identity);
    }

    /// <summary>
    /// Derives the exact ContactHello safety-number hash from two non-forked,
    /// verified account bindings. Device-directory changes do not enter this
    /// value; a destructive account-generation replacement does.
    /// </summary>
    public static byte[] ComputeContactSafetyNumber(
        Dab1LineageState first,
        Dab1LineageState second)
    {
        ArgumentNullException.ThrowIfNull(first);
        ArgumentNullException.ThrowIfNull(second);
        if (first.ForkLatched || second.ForkLatched)
            Reject("A forked account binding cannot authorize a contact safety number.");
        var left = first.Head.Identity.Account;
        var right = second.Head.Identity.Account;
        var network = left.Certificate.NetworkId.Span;
        var leftHash = left.Certificate.CanonicalHash.Span;
        var rightHash = right.Certificate.CanonicalHash.Span;
        if (!network.SequenceEqual(right.Certificate.NetworkId.Span) ||
            left.DeepAccountIdHash.Span.SequenceEqual(right.DeepAccountIdHash.Span) ||
            leftHash.SequenceEqual(rightHash))
            Reject("A contact safety number requires two distinct verified accounts on one network.");

        var lower = leftHash.SequenceCompareTo(rightHash) < 0 ? left : right;
        var upper = ReferenceEquals(lower, left) ? right : left;
        Span<byte> material = stackalloc byte[96];
        network.CopyTo(material);
        lower.Certificate.CanonicalHash.Span.CopyTo(material[16..48]);
        BinaryPrimitives.WriteUInt64BigEndian(material[48..56],
            lower.Certificate.AccountGeneration);
        upper.Certificate.CanonicalHash.Span.CopyTo(material[56..88]);
        BinaryPrimitives.WriteUInt64BigEndian(material[88..96],
            upper.Certificate.AccountGeneration);
        return ApplicationCoreFormat.Sha256Domain(
            "Deep/Application/V1/contact-safety-number", material);
    }

    /// <summary>
    /// Checks the identity-bound ContactHello fields and embedded XUR1 using
    /// independently verified account/device closures. The caller must still
    /// prove that this DMC2 came from the authenticated initial DPH2 stage,
    /// verify the XUR1 placement closure, and commit contact/inbox state before
    /// acknowledging a mailbox deposit.
    /// </summary>
    public static void RequireContactHelloEndpointBindings(
        ParsedDmc2 hello,
        Dab1LineageState initiatorBinding,
        Dmd1LineageState initiatorDirectory,
        Dab1LineageState recipientBinding)
    {
        ArgumentNullException.ThrowIfNull(hello);
        ArgumentNullException.ThrowIfNull(initiatorBinding);
        ArgumentNullException.ThrowIfNull(initiatorDirectory);
        ArgumentNullException.ThrowIfNull(recipientBinding);
        if (hello.ParsedPayload is not ContactHelloDmc2Payload)
            Reject("The authenticated initial event is not ContactHello.");
        var payload = (ContactHelloDmc2Payload)hello.ParsedPayload;
        if (initiatorBinding.ForkLatched || initiatorDirectory.ForkLatched ||
            recipientBinding.ForkLatched)
            Reject("A forked account or device lineage cannot authorize ContactHello.");

        var initiator = initiatorBinding.Head.Identity;
        var directory = initiatorDirectory.Head;
        var recipient = recipientBinding.Head.Identity;
        var network = hello.NetworkId.Span;
        if (!network.SequenceEqual(initiator.Account.Certificate.NetworkId.Span) ||
            !network.SequenceEqual(recipient.Account.Certificate.NetworkId.Span) ||
            !network.SequenceEqual(directory.Record.NetworkId.Span) ||
            !hello.SenderAccountId.Span.SequenceEqual(
                initiator.Account.DeepAccountIdHash.Span) ||
            !directory.Record.DeepAccountId.Span.SequenceEqual(
                initiator.Account.DeepAccountIdHash.Span) ||
            !initiator.Account.Certificate.CanonicalHash.Span.SequenceEqual(
                directory.Identity.Account.Certificate.CanonicalHash.Span) ||
            !initiator.Revocations.Snapshot.CanonicalHash.Span.SequenceEqual(
                directory.Identity.Revocations.Snapshot.CanonicalHash.Span))
            Reject("ContactHello differs from the verified account/directory closure.");

        var device = directory.Identity.ActiveDevices.SingleOrDefault(candidate =>
            candidate.Certificate.DeviceId.Span.SequenceEqual(hello.SenderDeviceId.Span)) ??
            throw ApplicationCoreFormat.Error(
                ApplicationCoreValidationStage.CryptographicVerification,
                ApplicationCoreRejection.VerificationFailed,
                "ContactHello sender is not an active verified initiator device.");
        if (!directory.Record.ActiveDevices.Any(candidate =>
                candidate.DeviceId.Span.SequenceEqual(hello.SenderDeviceId.Span)))
            Reject("ContactHello sender is not an active verified initiator device.");

        var expectedDab1 = new ContactArtifactReference(
            ProtocolMagic.DAB1, 1, initiatorBinding.Head.Record.RecordHash.Span);
        var expectedSafety = ComputeContactSafetyNumber(
            initiatorBinding, recipientBinding);
        try
        {
            if (!payload.InitiatorDab1Reference.Span.SequenceEqual(
                    expectedDab1.CanonicalBytes.Span) ||
                !CryptographicOperations.FixedTimeEquals(
                    payload.InitiatorDmd1Hash.Span,
                    directory.Record.RecordHash.Span) ||
                !CryptographicOperations.FixedTimeEquals(
                    payload.SafetyNumberHash.Span, expectedSafety))
                Reject("ContactHello DAB1, DMD1, or safety number differs from verified authority.");
        }
        finally { CryptographicOperations.ZeroMemory(expectedSafety); }

        var xur1 = ContactCodec.Decode(ProtocolMagic.XUR1, payload.InboundXur1.Span);
        var dpd1Reference = ContactCodec.DecodeArtifactReference(
            xur1.FieldSpan(14), ProtocolMagic.DPD1);
        var createdAtSeconds = hello.CreatedAtUnixMilliseconds / 1_000;
        if (!xur1.FieldSpan(1).SequenceEqual(network) ||
            !xur1.FieldSpan(13).SequenceEqual(hello.SenderDeviceId.Span) ||
            !dpd1Reference.Hash.Span.SequenceEqual(device.Certificate.CanonicalHash.Span) ||
            BinaryPrimitives.ReadUInt16BigEndian(xur1.FieldSpan(10)) != 0x0007 ||
            BinaryPrimitives.ReadUInt64BigEndian(xur1.FieldSpan(11)) > createdAtSeconds ||
            BinaryPrimitives.ReadUInt64BigEndian(xur1.FieldSpan(12)) <= createdAtSeconds ||
            device.Certificate.IssuedAtUnixSeconds > createdAtSeconds ||
            device.Certificate.ExpiresAtUnixSeconds <= createdAtSeconds)
            Reject("ContactHello XUR1 is outside its verified author/device/time scope.");
        ContactCodec.VerifyDeviceSignature(
            xur1, device.Certificate.DeviceEd25519PublicKey.Span);
    }

    public static VerifiedDmd1 VerifyDmd1(
        ParsedDmd1 parsed,
        VerifiedApplicationIdentityClosure identity)
    {
        ArgumentNullException.ThrowIfNull(parsed);
        ArgumentNullException.ThrowIfNull(identity);
        var account = identity.Account;
        if (!parsed.NetworkId.Span.SequenceEqual(account.Certificate.NetworkId.Span) ||
            !parsed.DeepAccountId.Span.SequenceEqual(account.DeepAccountIdHash.Span) ||
            parsed.AccountGeneration != account.Certificate.AccountGeneration ||
            !References(parsed.Dpa1Reference, account.Certificate) ||
            !References(parsed.Drs1Reference, identity.Revocations.Snapshot) ||
            parsed.ActiveDevices.Count != identity.ActiveDevices.Count)
            Reject("DMD1 does not close over the exact DPA1/DRS1 identity state.");

        foreach (var entry in parsed.ActiveDevices)
        {
            if (!identity.TryGetDevice(entry.DeviceId.Span, out var device) || device is null ||
                !References(entry.Dpd1Reference, device.Certificate))
                Reject("DMD1 contains a missing, changed, or unverified DPD1 entry.");
        }
        VerifySignature(parsed.DeviceIssuerSignature.Span, parsed.SignatureInput.Span,
            account.Certificate.DeviceIssuerEd25519PublicKey.Span, "DMD1 device-issuer signature");
        return new VerifiedDmd1(parsed, identity);
    }

    public static VerifiedDca1 VerifyDca1(
        ParsedDca1 parsed,
        VerifiedDab1 binding,
        VerifiedDmd1 directory)
    {
        ArgumentNullException.ThrowIfNull(parsed);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(directory);
        if (!ReferenceEquals(binding.Identity, directory.Identity))
            Reject("DCA1 binding and directory do not share one verified identity closure.");
        var account = binding.Identity.Account;
        if (!parsed.NetworkId.Span.SequenceEqual(account.Certificate.NetworkId.Span) ||
            !parsed.DeepAccountId.Span.SequenceEqual(account.DeepAccountIdHash.Span) ||
            !References(parsed.Dpa1Reference, account.Certificate) ||
            parsed.AuthorizedDmd1Generation != directory.Record.DirectoryGeneration ||
            !parsed.AuthorizedDmd1Hash.Span.SequenceEqual(directory.Record.RecordHash.Span) ||
            !parsed.ExactDid1Hash.Span.SequenceEqual(binding.DeepId.RecordHash.Span) ||
            parsed.Dab1Reference.TypeCode != ApplicationCoreCodec.Dab1ArtifactTypeCode ||
            parsed.Dab1Reference.CanonicalLength != binding.Record.CanonicalBytes.Length ||
            !parsed.Dab1Reference.CanonicalHash.Span.SequenceEqual(binding.Record.RecordHash.Span) ||
            !directory.Record.ActiveDevices.Any(entry =>
                entry.DeviceId.Span.SequenceEqual(parsed.PublisherDeviceId.Span)))
            Reject("DCA1 does not close over exact DID1/DAB1/DPA1/DMD1 state or an active publisher.");
        VerifySignature(parsed.AccountSignature.Span, parsed.SignatureInput.Span,
            account.Certificate.AccountEd25519PublicKey.Span, "DCA1 account signature");
        return new VerifiedDca1(parsed, binding, directory);
    }

    public static CurrentlyAuthoritativeDca1 RequireDca1CurrentlyAuthoritative(
        VerifiedDca1 verified,
        ulong trustedUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(verified);
        if (trustedUnixSeconds < verified.Record.NotBeforeUnixSeconds ||
            trustedUnixSeconds >= verified.Record.ExpiresAtUnixSeconds)
            Reject("DCA1 is not currently authoritative at the trusted instant.");
        return new CurrentlyAuthoritativeDca1(verified, trustedUnixSeconds);
    }

    public static Dab1LineageTransitionPlan StartDab1Lineage(VerifiedDab1 genesis)
    {
        ArgumentNullException.ThrowIfNull(genesis);
        if (genesis.Record.BindingGeneration != 0 ||
            !ApplicationCoreFormat.IsZero(genesis.Record.PredecessorDab1Hash.Span))
            Lineage("A DAB1 lineage starts at generation zero with a zero predecessor.");
        var initial = new Dab1LineageState(genesis, forkLatched: false);
        return new Dab1LineageTransitionPlan(initial, initial, ApplicationLineageDisposition.AcceptedGenesis);
    }

    public static Dab1LineageTransitionPlan PrepareDab1Transition(
        Dab1LineageState previous,
        VerifiedDab1 candidate)
    {
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(candidate);
        EnsureNotLatched(previous.ForkLatched);
        var head = previous.Head.Record;
        var next = candidate.Record;
        if (!head.IdentityRealmId.Span.SequenceEqual(next.IdentityRealmId.Span) ||
            !head.ExactDid1Hash.Span.SequenceEqual(next.ExactDid1Hash.Span))
            Lineage("DAB1 lineages from different permanent Deep IDs cannot be combined.");
        if (next.BindingGeneration == head.BindingGeneration)
            return SameGeneration(previous, candidate);
        if (head.BindingGeneration == ulong.MaxValue)
            Lineage("A DAB1 lineage cannot advance beyond its maximum generation.");
        if (next.BindingGeneration != head.BindingGeneration + 1 ||
            !next.PredecessorDab1Hash.Span.SequenceEqual(head.RecordHash.Span))
            Lineage("DAB1 must advance exactly one generation and bind the exact predecessor head.");
        var accepted = new Dab1LineageState(candidate, forkLatched: false);
        return new Dab1LineageTransitionPlan(previous, accepted, ApplicationLineageDisposition.AcceptedSuccessor);
    }

    public static Dmd1LineageTransitionPlan StartDmd1Lineage(VerifiedDmd1 genesis)
    {
        ArgumentNullException.ThrowIfNull(genesis);
        if (genesis.Record.DirectoryGeneration != 1 ||
            !ApplicationCoreFormat.IsZero(genesis.Record.PredecessorDmd1Hash.Span))
            Lineage("A DMD1 lineage starts at generation one with a zero predecessor.");
        var initial = new Dmd1LineageState(genesis, forkLatched: false);
        return new Dmd1LineageTransitionPlan(initial, initial, ApplicationLineageDisposition.AcceptedGenesis);
    }

    public static Dmd1LineageTransitionPlan PrepareDmd1Transition(
        Dmd1LineageState previous,
        VerifiedDmd1 candidate)
    {
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(candidate);
        EnsureNotLatched(previous.ForkLatched);
        var head = previous.Head.Record;
        var next = candidate.Record;
        if (!head.NetworkId.Span.SequenceEqual(next.NetworkId.Span) ||
            !head.DeepAccountId.Span.SequenceEqual(next.DeepAccountId.Span))
            Lineage("DMD1 lineages from different accounts cannot be combined.");
        if (next.DirectoryGeneration == head.DirectoryGeneration)
            return SameGeneration(previous, candidate);
        if (head.DirectoryGeneration == ulong.MaxValue)
            Lineage("A DMD1 lineage cannot advance beyond its maximum generation.");
        if (next.DirectoryGeneration != head.DirectoryGeneration + 1 ||
            !next.PredecessorDmd1Hash.Span.SequenceEqual(head.RecordHash.Span))
            Lineage("DMD1 must advance exactly one generation and bind the exact predecessor head.");
        var accepted = new Dmd1LineageState(candidate, forkLatched: false);
        return new Dmd1LineageTransitionPlan(previous, accepted, ApplicationLineageDisposition.AcceptedSuccessor);
    }

    public static VerifiedDmc2 VerifyDmc2(
        VerifiedDpe2Envelope authenticatedEnvelope)
    {
        ArgumentNullException.ThrowIfNull(authenticatedEnvelope);
        var parsed = authenticatedEnvelope.UseAuthenticatedPlaintext(
            static plaintext => ApplicationCoreCodec.DecodeDmc2(plaintext));
        if (!parsed.NetworkId.Span.SequenceEqual(authenticatedEnvelope.NetworkId.Span) ||
            !parsed.SenderAccountId.Span.SequenceEqual(authenticatedEnvelope.SenderAccountId.Span) ||
            !parsed.SenderDeviceId.Span.SequenceEqual(authenticatedEnvelope.SenderDeviceId.Span) ||
            !parsed.ConversationId.Span.SequenceEqual(authenticatedEnvelope.ConversationId.Span))
            Reject("DMC2 does not equal the authenticated DPE2/ratchet sender and conversation context.");
        return new VerifiedDmc2(parsed, parsed.ParsedPayload, authenticatedEnvelope);
    }

    private static Dab1LineageTransitionPlan SameGeneration(
        Dab1LineageState previous,
        VerifiedDab1 candidate)
    {
        if (previous.Head.Record.RecordHash.Span.SequenceEqual(candidate.Record.RecordHash.Span))
            return new Dab1LineageTransitionPlan(previous, previous, ApplicationLineageDisposition.ExactReplay);
        var latched = new Dab1LineageState(previous.Head, forkLatched: true);
        return new Dab1LineageTransitionPlan(previous, latched, ApplicationLineageDisposition.ForkLatched);
    }

    private static Dmd1LineageTransitionPlan SameGeneration(
        Dmd1LineageState previous,
        VerifiedDmd1 candidate)
    {
        if (previous.Head.Record.RecordHash.Span.SequenceEqual(candidate.Record.RecordHash.Span))
            return new Dmd1LineageTransitionPlan(previous, previous, ApplicationLineageDisposition.ExactReplay);
        var latched = new Dmd1LineageState(previous.Head, forkLatched: true);
        return new Dmd1LineageTransitionPlan(previous, latched, ApplicationLineageDisposition.ForkLatched);
    }

    private static void EnsureNotLatched(bool forkLatched)
    {
        if (forkLatched)
            throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.CryptographicVerification,
                ApplicationCoreRejection.InvalidLineage, "The application lineage is permanently fork-latched.");
    }

    private static bool SameAccount(VerifiedAccount left, VerifiedAccount right) =>
        SameArtifact(left.Certificate, right.Certificate) &&
        left.DeepAccountIdHash.Span.SequenceEqual(right.DeepAccountIdHash.Span);

    private static bool SameArtifact(CanonicalIdentityArtifact left, CanonicalIdentityArtifact right) =>
        left.ArtifactType == right.ArtifactType &&
        left.CanonicalBytes.Length == right.CanonicalBytes.Length &&
        left.CanonicalHash.Span.SequenceEqual(right.CanonicalHash.Span);

    private static bool References(ApplicationArtifactReference reference, CanonicalIdentityArtifact artifact) =>
        reference.TypeCode == (ushort)artifact.ArtifactType &&
        reference.CanonicalLength == artifact.CanonicalBytes.Length &&
        reference.CanonicalHash.Span.SequenceEqual(artifact.CanonicalHash.Span);

    private static void VerifySignature(
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> input,
        ReadOnlySpan<byte> publicKey,
        string name)
    {
        if (!PublicKeyAuth.VerifyDetached(signature.ToArray(), input.ToArray(), publicKey.ToArray()))
            Reject($"{name} is invalid.");
    }

    private static void Reject(string message) =>
        throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.CryptographicVerification,
            ApplicationCoreRejection.VerificationFailed, message);

    private static void Lineage(string message) =>
        throw ApplicationCoreFormat.Error(ApplicationCoreValidationStage.CryptographicVerification,
            ApplicationCoreRejection.InvalidLineage, message);
}
