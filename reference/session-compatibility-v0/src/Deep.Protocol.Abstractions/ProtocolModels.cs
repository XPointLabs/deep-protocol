namespace Deep.Protocol.Abstractions;

public sealed record Destination
{
    public DestinationType Type { get; init; }
    public ReadOnlyMemory<byte> ProRotatingEd25519PrivateKey { get; init; }
    public DateTimeOffset SentTimestamp { get; init; }
    public ReadOnlyMemory<byte> RecipientPublicKey { get; init; }
    public ReadOnlyMemory<byte> CommunityInboxServerPublicKey { get; init; }
    public ReadOnlyMemory<byte> GroupEd25519PublicKey { get; init; }
    public ReadOnlyMemory<byte> GroupEncryptionKey { get; init; }
}

public sealed record ProtocolEnvelope
{
    public EnvelopeFlags Flags { get; init; }
    public DateTimeOffset Timestamp { get; init; }
    public ReadOnlyMemory<byte> Source { get; init; }
    public uint SourceDevice { get; init; }
    public ulong ServerTimestamp { get; init; }
    public ReadOnlyMemory<byte> ProSignature { get; init; }
}

public sealed record ProProof
{
    public byte Version { get; init; }
    public ReadOnlyMemory<byte> GenerationIndexHash { get; init; }
    public ReadOnlyMemory<byte> RotatingPublicKey { get; init; }
    public DateTimeOffset ExpiryUnixTime { get; init; }
    public ReadOnlyMemory<byte> Signature { get; init; }
}

public sealed record ProSignedMessage(ReadOnlyMemory<byte> Signature, ReadOnlyMemory<byte> Message);

public sealed record ProMessageBitset(ulong Data)
{
    public bool IsSet(ProMessageFeature feature) => (Data & (1UL << (int)feature)) != 0;
    public ProMessageBitset Set(ProMessageFeature feature) => this with { Data = Data | (1UL << (int)feature) };
    public ProMessageBitset Unset(ProMessageFeature feature) => this with { Data = Data & ~(1UL << (int)feature) };
}

public sealed record ProProfileBitset(ulong Data)
{
    public bool IsSet(ProProfileFeature feature) => (Data & (1UL << (int)feature)) != 0;
    public ProProfileBitset Set(ProProfileFeature feature) => this with { Data = Data | (1UL << (int)feature) };
    public ProProfileBitset Unset(ProProfileFeature feature) => this with { Data = Data & ~(1UL << (int)feature) };
}

public sealed record ProFeaturesForMessage(
    ProFeaturesForMessageStatus Status,
    string? Error,
    ProMessageBitset Bitset,
    int CodepointCount);

public sealed record DecodedPro
{
    public ProStatus Status { get; init; }
    public ProProof Proof { get; init; } = new();
    public ProMessageBitset MessageBitset { get; init; } = new(0);
    public ProProfileBitset ProfileBitset { get; init; } = new(0);
}

public sealed record DecodeEnvelopeKeys
{
    public ReadOnlyMemory<byte>? GroupEd25519PublicKey { get; init; }
    public IReadOnlyList<ReadOnlyMemory<byte>> DecryptKeys { get; init; } = Array.Empty<ReadOnlyMemory<byte>>();
}

public sealed record DecodedEnvelope
{
    public ProtocolEnvelope Envelope { get; init; } = new();
    public ReadOnlyMemory<byte> ContentPlaintext { get; init; }
    public ReadOnlyMemory<byte> SenderEd25519PublicKey { get; init; }
    public ReadOnlyMemory<byte> SenderX25519PublicKey { get; init; }
    public DecodedPro? Pro { get; init; }
}

public sealed record DecodedCommunityMessage
{
    public ProtocolEnvelope? Envelope { get; init; }
    public ReadOnlyMemory<byte> ContentPlaintext { get; init; }
    public ReadOnlyMemory<byte>? ProSignature { get; init; }
    public DecodedPro? Pro { get; init; }
}

public sealed record EncodedForDestination(ReadOnlyMemory<byte> Ciphertext);
