namespace Deep.Protocol.Abstractions.OnionRequests;

public enum OnionEncryptionType
{
    AesGcm,
    XChaCha20
}

public enum OnionPathCategory
{
    Standard,
    File
}

public sealed record OnionServiceNode(
    string Address,
    ReadOnlyMemory<byte> Ed25519PublicKey,
    ReadOnlyMemory<byte> X25519PublicKey);

public sealed record OnionPath(
    string Id,
    IReadOnlyList<OnionServiceNode> Nodes,
    DateTimeOffset CreatedAt,
    DateTimeOffset? EdgeFirstConnectedAt = null,
    OnionPathCategory Category = OnionPathCategory.Standard,
    int ActiveRequests = 0,
    int FailureCount = 0);

public sealed record OnionRequestBuildOptions
{
    public OnionEncryptionType EncryptionType { get; init; } = OnionEncryptionType.XChaCha20;
    public string Endpoint { get; init; } = string.Empty;
    public IReadOnlyList<OnionServiceNode> Hops { get; init; } = Array.Empty<OnionServiceNode>();
    public ReadOnlyMemory<byte> DestinationX25519PublicKey { get; init; }
}

public sealed record OnionRequestPayload(
    ReadOnlyMemory<byte> Body,
    ReadOnlyMemory<byte> FinalHopX25519PublicKey,
    ReadOnlyMemory<byte> FinalHopX25519SecretKey);

public sealed record OnionResponse(
    short StatusCode,
    IReadOnlyList<KeyValuePair<string, string>> Headers,
    string? Body);

public interface IOnionRequestCrypto
{
    OnionRequestPayload Build(OnionRequestBuildOptions options, ReadOnlySpan<byte> plaintextBody);

    OnionResponse DecryptResponse(
        OnionEncryptionType encryptionType,
        ReadOnlySpan<byte> destinationX25519PublicKey,
        ReadOnlySpan<byte> finalHopX25519PublicKey,
        ReadOnlySpan<byte> finalHopX25519SecretKey,
        ReadOnlySpan<byte> encryptedResponse,
        bool v4Request);
}
