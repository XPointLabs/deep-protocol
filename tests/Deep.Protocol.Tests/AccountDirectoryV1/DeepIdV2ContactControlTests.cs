using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Tests.Identity;
using Deep.Protocol.Tests.ContactV2;
using Sodium;
using ProtocolMagic = Deep.Protocol.Registry.DeepProtocolIdentifiers.Magic;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed partial class AccountDirectoryFreshnessVerificationTests
{
    [Fact]
    public void ContactConversationDerivation_ExactDomainAndEndpointSymmetry()
    {
        static byte[] Repeated(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
        var network = Repeated(16, 1); var relationship = Repeated(32, 2);
        var a = Repeated(32, 3); var b = Repeated(32, 4);
        var exact = ApplicationCoreVerifier.ComputeContactConversationId(network, relationship, a, b);
        Assert.Equal("5DF376969A08E345299DDE6328693EB27830A80C8F17F65EB1C770D3BEBD4E64", Convert.ToHexString(exact));
        Assert.Equal(exact, ApplicationCoreVerifier.ComputeContactConversationId(network, relationship, b, a));
        Assert.NotEqual(exact, ApplicationCoreVerifier.ComputeContactConversationId(network, Repeated(32, 5), a, b));
        Assert.Throws<ArgumentException>(() => ApplicationCoreVerifier.ComputeContactConversationId(network, relationship, a, a));
        Assert.Throws<ArgumentException>(() => ApplicationCoreVerifier.ComputeContactConversationId(new byte[16], relationship, a, b));
        Assert.Throws<ArgumentException>(() => ApplicationCoreVerifier.ComputeContactConversationId(network, new byte[32], a, b));
        Assert.Throws<ArgumentException>(() => ApplicationCoreVerifier.ComputeContactConversationId(new byte[17], relationship, a, b));
    }

    [Fact]
    public async Task Did2ContactControl_CurrentEndpointsOwnInputsAndRejectSubstitutions()
    {
        var sender = await RendezvousCurrentProof();
        var recipient = await RendezvousCurrentProof(sender.NetworkId.ToArray(),
            Dnp1IdentityAuthoringV1Tests.OtherMnemonic);
        var exactXur = ContactControlXur(sender);
        var rendezvous = await DeepIdV2ContactUpdateRendezvousVerifier.VerifyAsync(exactXur,
            sender, new OnionTrustedTimeAuthority(new RendezvousClock()));
        var created = checked((sender.TrustedUpperUnixSeconds + 3) * 1000);
        var expires = created + 60_000;
        var relationship = Bytes(32, 0xa1); var logical = Bytes(32, 0xa2);
        var conversation = ApplicationCoreVerifier.ComputeContactConversationId(sender.NetworkId.Span, relationship,
            sender.CurrentCheckpoint!.Binding.Record.DeepAccountId.Span, recipient.CurrentCheckpoint!.Binding.Record.DeepAccountId.Span);
        var originalRelationship = relationship.ToArray(); var originalLogical = logical.ToArray();
        var originalConversation = conversation.ToArray();
        // Endpoint-metadata fixture only; fake route signatures cannot pass the
        // independent full route verifier used by the connected native tests.
        var senderRoute = DeepIdV2ContactMailboxRouteCodec.Decode(DeepIdV2ContactMailboxRouteTests.Package(false, sender));
        var recipientRoute = DeepIdV2ContactMailboxRouteCodec.Decode(DeepIdV2ContactMailboxRouteTests.Package(false, recipient));
        var authored = await ApplicationCoreCodec.AuthorVerifiedContactHelloAsync(rendezvous, senderRoute, recipient,
            relationship, logical, conversation, created, expires,
            new OnionTrustedTimeAuthority(new RendezvousClock(onRead: () =>
            { relationship[0] ^= 1; logical[0] ^= 1; conversation[0] ^= 1; })));
        var hello = authored.Record;
        var payload = Assert.IsType<ContactHelloDmc2Payload>(hello.ParsedPayload);
        Assert.Equal(originalRelationship, payload.RelationshipId.ToArray());
        Assert.Equal(originalLogical, hello.LogicalMessageId.ToArray());
        Assert.Equal(originalConversation, hello.ConversationId.ToArray());
        Assert.Equal((ulong)2, hello.SenderClientSequence);
        var expectedReference = new ContactArtifactReference(ProtocolMagic.DAB2, 2,
            sender.CurrentCheckpoint!.Binding.Record.RecordHash.Span).CanonicalBytes;
        Assert.Equal(expectedReference.ToArray(), payload.InitiatorDab2Reference.ToArray());
        ValueTask Verify(ParsedDmc2 record, RendezvousClock? clock = null, CancellationToken ct = default) =>
            ApplicationCoreVerifier.RequireContactHelloEndpointBindingsAsync(record, sender, recipient,
                new OnionTrustedTimeAuthority(clock ?? new RendezvousClock()), ct);
        await Verify(hello);
        var responderXur = ContactControlXur(recipient);
        var responderRendezvous = await DeepIdV2ContactUpdateRendezvousVerifier.VerifyAsync(responderXur,
            recipient, new OnionTrustedTimeAuthority(new RendezvousClock()));
        var accepted = await ApplicationCoreCodec.AuthorVerifiedContactAcceptAsync(hello, sender,
            responderRendezvous, recipientRoute, Bytes(32, 0xa4), 1, created + 1000, expires + 1000,
            new OnionTrustedTimeAuthority(new RendezvousClock()));
        var accept = accepted.Record;
        var response = Assert.IsType<ContactAcceptDmc2Payload>(accept.ParsedPayload);
        Assert.Empty(typeof(AuthoredVerifiedContactAccept).GetConstructors());
        Assert.Equal(SHA256.HashData(hello.CanonicalBytes.Span), response.ContactHelloHash.ToArray());
        Assert.Equal(payload.RelationshipId.ToArray(), response.RelationshipId.ToArray());
        ValueTask VerifyAccept(ParsedDmc2 record, RendezvousClock? clock = null) =>
            ApplicationCoreVerifier.RequireContactAcceptEndpointBindingsAsync(record, hello, sender, recipient,
                new OnionTrustedTimeAuthority(clock ?? new RendezvousClock()));
        await VerifyAccept(accept);
        ParsedDmc2 ChangedAccept(int choice)
        {
            var rel = response.RelationshipId.ToArray(); var hash = response.ContactHelloHash.ToArray();
            var reference = response.ResponderDab2Reference.ToArray(); var directory = response.ResponderDmd1Hash.ToArray();
            if (choice == 0) rel[0] ^= 1;
            if (choice == 1) hash[0] ^= 1;
            if (choice == 2) reference[^1] ^= 1;
            if (choice == 3) directory[0] ^= 1;
            var replacement = ContactCodecValidation.CreateContactAcceptPayload(rel, hash, reference,
                directory, response.Policy, responderXur,
                choice == 9 ? senderRoute.ExactBytes.Span : response.MailboxRoute.ExactBytes.Span);
            return ContactCodecValidation.AuthorDmc2(accept.NetworkId.Span, accept.LogicalMessageId.Span,
                choice == 4 ? Bytes(32, 0xb3) : accept.ConversationId.Span,
                choice == 5 ? hello.SenderAccountId.Span : accept.SenderAccountId.Span,
                choice == 6 ? Bytes(32, 0xb4) : accept.SenderDeviceId.Span, 1,
                choice == 7 ? created - 1 : choice == 8 ? hello.ExpiresAtUnixMilliseconds : created + 1000,
                expires + 1000, Dmc2Flags.None, [], replacement);
        }
        for (var choice = 0; choice < 10; choice++)
            await Assert.ThrowsAnyAsync<CryptographicException>(async () => await VerifyAccept(ChangedAccept(choice)));
        foreach (var createClock in new Func<RendezvousClock>[] {
            () => new RendezvousClock(first: 1004, final: 1003),
            () => new RendezvousClock(finalBoot: Bytes(16, 0xc3)),
            () => new RendezvousClock(final: sender.FreshnessDeadlineMonotonicSeconds) })
        {
            await Assert.ThrowsAnyAsync<CryptographicException>(async () => await VerifyAccept(accept, createClock()));
            await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
                await ApplicationCoreCodec.AuthorVerifiedContactAcceptAsync(hello, sender, responderRendezvous,
                    recipientRoute, Bytes(32, 0xa4), 1, created + 1000, expires + 1000, new OnionTrustedTimeAuthority(createClock())));
        }
        ParsedDmc2 Changed(int choice)
        {
            var reference = payload.InitiatorDab2Reference.ToArray();
            var directory = payload.InitiatorDmd1Hash.ToArray();
            var safety = payload.SafetyNumberHash.ToArray();
            if (choice == 0) reference[^1] ^= 1;
            if (choice == 1) directory[0] ^= 1;
            if (choice == 2) safety[0] ^= 1;
            var replacement = ContactCodecValidation.CreateContactHelloPayload(originalRelationship,
                reference, directory, safety, payload.Policy, exactXur,
                choice == 9 ? recipientRoute.ExactBytes.Span : payload.MailboxRoute.ExactBytes.Span);
            return ContactCodecValidation.AuthorDmc2(choice == 3 ? Bytes(16, 0xb1) : hello.NetworkId.Span,
                originalLogical, choice == 8 ? Bytes(32, 0xa3) : originalConversation, choice == 4 ? recipient.CurrentCheckpoint!.Binding.Record.DeepAccountId.Span : hello.SenderAccountId.Span,
                choice == 5 ? Bytes(32, 0xb2) : hello.SenderDeviceId.Span, choice == 6 ? 1UL : 2UL,
                choice == 7 ? created - 100_000 : created, expires, Dmc2Flags.None, [], replacement);
        }
        for (var choice = 0; choice < 10; choice++)
            await Assert.ThrowsAnyAsync<CryptographicException>(async () => await Verify(Changed(choice)));
        foreach (var clock in new[] { new RendezvousClock(first: 1004, final: 1003),
            new RendezvousClock(finalBoot: Bytes(16, 0xc1)),
            new RendezvousClock(final: recipient.FreshnessDeadlineMonotonicSeconds),
            new RendezvousClock(first: 999) })
            await Assert.ThrowsAnyAsync<CryptographicException>(async () => await Verify(hello, clock));
        await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
            await ApplicationCoreCodec.AuthorVerifiedContactHelloAsync(rendezvous, senderRoute, sender,
                originalRelationship, originalLogical, originalConversation, created, expires,
                new OnionTrustedTimeAuthority(new RendezvousClock())));
        await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
            await ApplicationCoreCodec.AuthorVerifiedContactHelloAsync(rendezvous, senderRoute, recipient,
                originalRelationship, originalLogical, Bytes(32, 0xa3), created, expires,
                new OnionTrustedTimeAuthority(new RendezvousClock())));
        using var canceled = new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await Verify(hello,
            new RendezvousClock(onRead: canceled.Cancel), canceled.Token));
        foreach (var clock in new[] { new RendezvousClock(first: 1004, final: 1003),
            new RendezvousClock(finalBoot: Bytes(16, 0xc2)),
            new RendezvousClock(final: recipient.FreshnessDeadlineMonotonicSeconds) })
            await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
                await ApplicationCoreCodec.AuthorVerifiedContactHelloAsync(rendezvous, senderRoute, recipient,
                    originalRelationship, originalLogical, originalConversation, created, expires,
                    new OnionTrustedTimeAuthority(clock)));
        Assert.DoesNotContain(typeof(ApplicationCoreCodec).GetMethods(),
            method => method.Name == "AuthorVerifiedContactHello");
        Assert.DoesNotContain(typeof(ApplicationCoreVerifier).GetMethods(),
            method => method.Name is "RequireContactHelloEndpointBindings" or "ComputeContactSafetyNumber");
    }

    [Fact]
    public async Task Did2ContactControl_RetainedEndpointFactsDoNotRestoreExpiredRendezvous()
    {
        var sender = await RendezvousCurrentProof();
        var responder = await RendezvousCurrentProof(sender.NetworkId.ToArray(), Dnp1IdentityAuthoringV1Tests.OtherMnemonic);
        var senderXur = ContactControlXur(sender, sender.TrustedUpperUnixSeconds + 4);
        var responderXur = ContactControlXur(responder, responder.TrustedUpperUnixSeconds + 4);
        var senderRendezvous = await DeepIdV2ContactUpdateRendezvousVerifier.VerifyAsync(senderXur, sender,
            new OnionTrustedTimeAuthority(new RendezvousClock()));
        var responderRendezvous = await DeepIdV2ContactUpdateRendezvousVerifier.VerifyAsync(responderXur, responder,
            new OnionTrustedTimeAuthority(new RendezvousClock()));
        var senderRoute = DeepIdV2ContactMailboxRouteCodec.Decode(DeepIdV2ContactMailboxRouteTests.Package(false, sender));
        var responderRoute = DeepIdV2ContactMailboxRouteCodec.Decode(DeepIdV2ContactMailboxRouteTests.Package(false, responder));
        var relationship = Bytes(32, 0xe1);
        var conversation = ApplicationCoreVerifier.ComputeContactConversationId(sender.NetworkId.Span, relationship,
            sender.CurrentCheckpoint!.Binding.Record.DeepAccountId.Span, responder.CurrentCheckpoint!.Binding.Record.DeepAccountId.Span);
        var created = (sender.TrustedUpperUnixSeconds + 1) * 1000;
        var hello = (await ApplicationCoreCodec.AuthorVerifiedContactHelloAsync(senderRendezvous, senderRoute, responder,
            relationship, Bytes(32, 0xe2), conversation, created, created + 60_000,
            new OnionTrustedTimeAuthority(new RendezvousClock()))).Record;
        var accept = (await ApplicationCoreCodec.AuthorVerifiedContactAcceptAsync(hello, sender, responderRendezvous,
            responderRoute, Bytes(32, 0xe3), 3, created + 1000, created + 61_000,
            new OnionTrustedTimeAuthority(new RendezvousClock()))).Record;
        var later = sender.MonotonicSample + sender.TrustedUpperUnixSeconds - sender.TrustedLowerUnixSeconds + 20;
        OnionTrustedTimeAuthority Time() => new(new RendezvousClock(first: later, final: later));
        await ApplicationCoreVerifier.RequireRetainedContactHelloEndpointBindingsAsync(hello, sender, responder, Time());
        await ApplicationCoreVerifier.RequireRetainedContactAcceptEndpointBindingsAsync(accept, hello, sender, responder, Time());
        await Assert.ThrowsAsync<CryptographicException>(async () => await
            ApplicationCoreVerifier.RequireContactHelloEndpointBindingsAsync(hello, sender, responder, Time()));
        await Assert.ThrowsAsync<CryptographicException>(async () => await
            ApplicationCoreVerifier.RequireContactAcceptEndpointBindingsAsync(accept, hello, sender, responder, Time()));
        await Assert.ThrowsAsync<CryptographicException>(async () => await
            DeepIdV2ContactUpdateRendezvousVerifier.VerifyAsync(senderXur, sender, Time()));
        await Assert.ThrowsAsync<CryptographicException>(async () => await
            ApplicationCoreVerifier.RequireRetainedContactHelloEndpointBindingsAsync(hello, responder, sender, Time()));
        var future = ContactCodecValidation.AuthorDmc2(hello.NetworkId.Span, hello.LogicalMessageId.Span, hello.ConversationId.Span,
            hello.SenderAccountId.Span, hello.SenderDeviceId.Span, 2, created + 1000, created + 61_000,
            Dmc2Flags.None, [], hello.ParsedPayload);
        await Assert.ThrowsAsync<CryptographicException>(async () => await
            ApplicationCoreVerifier.RequireRetainedContactHelloEndpointBindingsAsync(future, sender, responder,
                new(new RendezvousClock())));
        var response = (ContactAcceptDmc2Payload)accept.ParsedPayload;
        ParsedDmc2 ChangedAccept(bool signature)
        {
            var original = ContactCodec.Decode(ProtocolMagic.XUR1, responderXur);
            var fields = Enumerable.Range(1, 15).Select(tag => (ReadOnlyMemory<byte>)original.Field(tag).ToArray()).ToArray();
            var badSignature = fields[14].ToArray(); badSignature[0] ^= 1; fields[14] = badSignature;
            var xur = signature ? ContactCodec.AuthorForValidation(ProtocolMagic.XUR1, fields).CanonicalBytes : responderXur;
            var payload = ContactCodecValidation.CreateContactAcceptPayload(response.RelationshipId.Span, response.ContactHelloHash.Span,
                response.ResponderDab2Reference.Span, response.ResponderDmd1Hash.Span, response.Policy, xur.Span, response.MailboxRoute.ExactBytes.Span);
            return ContactCodecValidation.AuthorDmc2(accept.NetworkId.Span, accept.LogicalMessageId.Span, accept.ConversationId.Span,
                accept.SenderAccountId.Span, accept.SenderDeviceId.Span, 3, signature ? created + 1000 : created + 10_000,
                created + 61_000, Dmc2Flags.None, [], payload);
        }
        foreach (var changed in new[] { ChangedAccept(true), ChangedAccept(false) })
            await Assert.ThrowsAsync<CryptographicException>(async () => await
                ApplicationCoreVerifier.RequireRetainedContactAcceptEndpointBindingsAsync(changed, hello, sender, responder, Time()));
        foreach (var clock in new[] { new RendezvousClock(first: later, final: later - 1),
            new RendezvousClock(first: later, final: later, finalBoot: Bytes(16, 0xe4)),
            new RendezvousClock(first: sender.FreshnessDeadlineMonotonicSeconds, final: sender.FreshnessDeadlineMonotonicSeconds) })
            await Assert.ThrowsAsync<CryptographicException>(async () => await
                ApplicationCoreVerifier.RequireRetainedContactHelloEndpointBindingsAsync(hello, sender, responder, new(clock)));
        using var canceled = new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await
            ApplicationCoreVerifier.RequireRetainedContactHelloEndpointBindingsAsync(hello, sender, responder,
                new(new RendezvousClock(first: later, final: later, onRead: canceled.Cancel)), canceled.Token));
    }

    private static byte[] ContactControlXur(VerifiedDeepIdV2DirectoryFreshness freshness, ulong? expiry = null)
    {
        var device = Assert.Single(freshness.CurrentCheckpoint!.Directory.Identity.ActiveDevices).Certificate;
        var key = PublicKeyAuth.GenerateKeyPair(Enumerable.Range(1, 32).Select(value => (byte)value).ToArray());
        try
        {
            Assert.Equal(device.DeviceEd25519PublicKey.ToArray(), key.PublicKey);
            ReadOnlyMemory<byte>[] fields = [freshness.NetworkId, Bytes(32, 0x81), Bytes(32, 0x82),
                RendezvousU64(0), new byte[32],
                new ContactArtifactReference(ProtocolMagic.PMT2, 1, Bytes(32, 0x83)).CanonicalBytes,
                Bytes(32, 0x84), Bytes(32, 0x85), Bytes(32, 0x86), new byte[] { 0, 7 },
                RendezvousU64(freshness.TrustedLowerUnixSeconds - 1), RendezvousU64(expiry ?? freshness.TrustedUpperUnixSeconds + 30),
                device.DeviceId, new ContactArtifactReference(ProtocolMagic.DPD1, 1, device.CanonicalHash.Span).CanonicalBytes,
                Bytes(64, 0x87)];
            var provisional = ContactCodec.AuthorForValidation(ProtocolMagic.XUR1, fields);
            fields[14] = PublicKeyAuth.SignDetached(provisional.SignatureInput.ToArray(), key.PrivateKey);
            return ContactCodec.AuthorForValidation(ProtocolMagic.XUR1, fields).CanonicalBytes.ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(key.PrivateKey); }
    }
}
