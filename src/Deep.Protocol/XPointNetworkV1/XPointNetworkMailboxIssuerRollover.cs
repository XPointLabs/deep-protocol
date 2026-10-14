namespace Deep.Protocol.XPointNetworkV1;

/// <summary>Public offline role-replacement intent, never signing custody or a verified capability.</summary>
public sealed class XPointNetworkMailboxIssuerRollover
{
    private readonly byte[] deposit, retrieve;
    public XPointNetworkMailboxIssuerRollover(ReadOnlySpan<byte> depositIssuerPublicKey,
        ReadOnlySpan<byte> retrieveIssuerPublicKey, ulong minimumGrantGeneration)
    {
        if (depositIssuerPublicKey.Length != 32 || retrieveIssuerPublicKey.Length != 32 ||
            depositIssuerPublicKey.IndexOfAnyExcept((byte)0) < 0 || retrieveIssuerPublicKey.IndexOfAnyExcept((byte)0) < 0 ||
            depositIssuerPublicKey.SequenceEqual(retrieveIssuerPublicKey) || minimumGrantGeneration == 0)
            throw new ArgumentException("Mailbox rollover requires distinct nonzero32-byte role keys and a nonzero grant floor.");
        deposit = depositIssuerPublicKey.ToArray(); retrieve = retrieveIssuerPublicKey.ToArray();
        MinimumGrantGeneration = minimumGrantGeneration;
    }
    public ReadOnlyMemory<byte> DepositIssuerPublicKey => deposit.ToArray();
    public ReadOnlyMemory<byte> RetrieveIssuerPublicKey => retrieve.ToArray();
    public ulong MinimumGrantGeneration { get; }
}
