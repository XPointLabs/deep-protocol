namespace Deep.Protocol.ContactV2;

/// <summary>Closed artifact-specific current witness signing request. No public
/// constructor, caller-selected signing purpose or authority conversion.</summary>
public sealed class PublicationLeaseSigningRequest
{
    private readonly byte[] input, network, hash;
    internal PublicationLeaseSigningRequest(ReadOnlySpan<byte> network, ReadOnlySpan<byte> hash, ReadOnlySpan<byte> input)
    { this.network = network.ToArray(); this.hash = hash.ToArray(); this.input = input.ToArray(); }
    public ReadOnlyMemory<byte> NetworkId => network.ToArray();
    public ReadOnlyMemory<byte> OriginalRequestHash => hash.ToArray();
    public ReadOnlyMemory<byte> SigningInput => input.ToArray();
}

public interface IDeepIdV2PublicationLeaseWitnessSigner
{
    ReadOnlyMemory<byte> WitnessId { get; }
    ValueTask<ReadOnlyMemory<byte>> SignPublicationLeaseAsync(PublicationLeaseSigningRequest request, CancellationToken ct);
}
