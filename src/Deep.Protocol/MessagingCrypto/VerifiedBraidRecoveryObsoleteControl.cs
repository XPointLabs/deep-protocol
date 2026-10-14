namespace Deep.Protocol.MessagingCrypto;

// Closed read-only proof for one actual native predecessor and exact public
// object. It is NOT native receive, a commit receipt, dispatch or ACK authority.
public sealed class VerifiedBraidRecoveryObsoleteControl
{
    private readonly byte[] stateCommitment, controlHash;
    internal VerifiedBraidRecoveryObsoleteControl(ulong stateGeneration, ReadOnlySpan<byte> stateCommitment,
        ulong braidEpoch, ReadOnlySpan<byte> controlHash)
    {
        StateGeneration = stateGeneration; BraidEpoch = braidEpoch;
        this.stateCommitment = stateCommitment.ToArray(); this.controlHash = controlHash.ToArray();
    }
    public ulong StateGeneration { get; }
    public ulong BraidEpoch { get; }
    public ReadOnlyMemory<byte> StateCommitment => stateCommitment.ToArray();
    public ReadOnlyMemory<byte> ExactControlHash => controlHash.ToArray();
}
