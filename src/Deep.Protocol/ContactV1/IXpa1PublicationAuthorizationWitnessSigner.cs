using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.ContactV1;

/// <summary>Custody contract; the DID2 author independently verifies identity,
/// purpose-domain signatures and current threshold. This interface alone grants no authority.</summary>
public interface IXpa1PublicationAuthorizationWitnessSigner
{
    ReadOnlyMemory<byte> WitnessId { get; }
    ValueTask<ReadOnlyMemory<byte>> SignXpa1Async(ReadOnlyMemory<byte> signingInput,
        CancellationToken cancellationToken);
}
