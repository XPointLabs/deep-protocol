using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class AuthenticatedMailboxMalformedAndFuzzTests
{
    [Fact]
    public void Mcp2RejectsEveryTruncationAndCriticalMutation()
    {
        var encoded = ValidPresentation();
        for (var length = 0; length < encoded.Length; length++)
            Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
                MailboxAuthenticatedCapabilityCodec.DecodePresentation(encoded.AsSpan(0, length)));

        foreach (var offset in new[] { 4, 5, 6, 66, 72 + 4, 72 + 5, 72 + 7 })
        {
            var mutated = encoded.ToArray();
            mutated[offset] = 0xff;
            Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
                MailboxAuthenticatedCapabilityCodec.DecodePresentation(mutated));
        }
        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            MailboxAuthenticatedCapabilityCodec.DecodePresentation([.. encoded, (byte)0]));
    }

    [Fact]
    public void FixedSeedMalformedSmoke_IsBoundedAndFailClosed()
    {
        var random = new Random(0x4d435032);
        for (var iteration = 0; iteration < 1000; iteration++)
        {
            var bytes = new byte[random.Next(0, 2048)];
            random.NextBytes(bytes);
            TryDecode(() => MailboxAuthenticatedCapabilityCodec.DecodePresentation(bytes));
            TryDecode(() => MailboxPeerReplicationCodec.Decode(bytes));
            TryDecode(() => MailboxPeerReplicationCodec.DecodeMembershipProof(bytes));
            TryDecode(() => MailboxAggregateAckCodec.Decode(bytes));
        }
    }

    [Fact]
    public void Mip1RejectsUnknownVersionReservedTrailingAndOversizedProof()
    {
        var proof = new MailboxReplicaMembershipProof
        {
            ReplicaId = Range(0x10, 32),
            SigningPublicKey = Range(0x30, 32),
            Epoch = 7,
            MembershipCommitment = Range(0x50, 32),
            CanonicalInclusionProof = Range(0x70, 64)
        };
        var encoded = MailboxPeerReplicationCodec.EncodeMembershipProof(proof);
        foreach (var offset in new[] { 4, 5, 114 })
        {
            var mutated = encoded.ToArray();
            mutated[offset] ^= 1;
            Assert.Throws<MailboxPeerReplicationException>(() =>
                MailboxPeerReplicationCodec.DecodeMembershipProof(mutated));
        }
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerReplicationCodec.DecodeMembershipProof([.. encoded, (byte)0]));
        Assert.Throws<MailboxPeerReplicationException>(() =>
            MailboxPeerReplicationCodec.EncodeMembershipProof(proof with
            {
                CanonicalInclusionProof =
                    new byte[MailboxPeerReplicationLimits.MaximumInclusionProofLength + 1]
            }));
    }

    private static byte[] ValidPresentation()
    {
        var crypto = new SodiumMailboxCapabilityCrypto();
        var issuer = Range(0x10, 32);
        var holder = Range(0x40, 32);
        var grant = crypto.SignGrant(new MailboxAuthenticatedGrant
        {
            Domain = MailboxCapabilityDomain.Deposit,
            Lifecycle = MailboxCapabilityLifecycle.Active,
            NetworkId = Range(0x70, 16),
            Epoch = 7,
            Generation = 9,
            Serial = Range(0x80, 16),
            NotBeforeUnixSeconds = 1000,
            ExpiresAtUnixSeconds = 1100,
            OverlapUntilUnixSeconds = 0,
            PlacementCommitment = Range(0x90, 32),
            MembershipCommitment = Range(0xb0, 32),
            IssuerPublicKey = crypto.GetPublicKey(issuer),
            HolderPublicKey = crypto.GetPublicKey(holder),
            IssuerSignature = ReadOnlyMemory<byte>.Empty
        }, issuer);
        return MailboxAuthenticatedCapabilityCodec.EncodePresentation(
            crypto.SignPresentation(
                grant,
                new MailboxAuthenticatedRequestBinding
                {
                    Operation = MailboxAuthenticatedOperation.Store,
                    OperationId = Range(0xd0, 16),
                    RequestDigest = Range(0xe0, 32)
                },
                11,
                holder));
    }

    private static void TryDecode(Action action)
    {
        try
        {
            action();
        }
        catch (MailboxAuthenticatedCapabilityException)
        {
        }
        catch (MailboxPeerReplicationException)
        {
        }
        catch (MailboxReceiptException)
        {
        }
    }

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => unchecked((byte)value)).ToArray();
}
