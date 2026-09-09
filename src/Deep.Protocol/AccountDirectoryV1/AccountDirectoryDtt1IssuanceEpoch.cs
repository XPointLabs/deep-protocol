using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.AccountDirectoryV1;

/// <summary>
/// Protocol-minted, authority-bound replay namespace for one DTT1 issuance day.
/// The identifier commits to the exact XNA1 authority, DTS1 policy and UTC day;
/// callers cannot supply a raw epoch identifier.
/// </summary>
public sealed class AccountDirectoryDtt1IssuanceEpoch
{
    public const ulong DurationSeconds = 86_400;
    private const string Domain = "Deep/AccountDirectory/V1/DTT1/issuance-epoch";
    private readonly byte[] networkId;
    private readonly byte[] authorityCoreReference;
    private readonly byte[] timeSourcePolicyCoreReference;
    private readonly byte[] id;

    private AccountDirectoryDtt1IssuanceEpoch(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> authorityCoreReference,
        ReadOnlySpan<byte> timeSourcePolicyCoreReference,
        ulong number,
        ulong validFrom,
        ulong validUntil,
        ReadOnlySpan<byte> id)
    {
        this.networkId = networkId.ToArray();
        this.authorityCoreReference = authorityCoreReference.ToArray();
        this.timeSourcePolicyCoreReference = timeSourcePolicyCoreReference.ToArray();
        Number = number;
        ValidFrom = validFrom;
        ValidUntil = validUntil;
        this.id = id.ToArray();
    }

    public ulong Number { get; }
    public ulong ValidFrom { get; }
    public ulong ValidUntil { get; }
    public ReadOnlyMemory<byte> Id => id.ToArray();

    public static AccountDirectoryDtt1IssuanceEpoch Derive(
        VerifiedXPointNetworkAuthority authority,
        ulong observedUnixTime,
        uint uncertaintySeconds)
    {
        ArgumentNullException.ThrowIfNull(authority);
        if (uncertaintySeconds > authority.MaximumWitnessUncertaintySeconds ||
            observedUnixTime < uncertaintySeconds ||
            observedUnixTime > ulong.MaxValue - uncertaintySeconds)
            throw new CryptographicException("The trusted interval cannot identify a DTT1 issuance epoch.");

        var lower = observedUnixTime - uncertaintySeconds;
        var upper = observedUnixTime + uncertaintySeconds;
        var number = observedUnixTime / DurationSeconds;
        var validFrom = checked(number * DurationSeconds);
        var validUntil = checked(validFrom + DurationSeconds - 1);
        if (lower < validFrom || upper > validUntil ||
            lower < authority.Dts1NotBefore || upper > authority.Dts1ExpiresAt)
            throw new CryptographicException(
                "The trusted interval crosses an issuance-epoch or DTS1 policy boundary.");

        Span<byte> payload = stackalloc byte[38 + 38 + 8];
        authority.AuthorityCoreReference.Span.CopyTo(payload);
        authority.Dts1PolicyCoreReference.Span.CopyTo(payload[38..]);
        BinaryPrimitives.WriteUInt64BigEndian(payload[76..], number);
        var epochId = AccountDirectoryCrypto.Sha256Domain(Domain, payload);
        try
        {
            return new AccountDirectoryDtt1IssuanceEpoch(
                authority.NetworkId.Span,
                authority.AuthorityCoreReference.Span,
                authority.Dts1PolicyCoreReference.Span,
                number,
                validFrom,
                validUntil,
                epochId);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            CryptographicOperations.ZeroMemory(epochId);
        }
    }

    internal void RequireAuthority(VerifiedXPointNetworkAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);
        if (!CryptographicOperations.FixedTimeEquals(networkId, authority.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                authorityCoreReference, authority.AuthorityCoreReference.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                timeSourcePolicyCoreReference, authority.Dts1PolicyCoreReference.Span))
            throw new CryptographicException("The DTT1 issuance epoch belongs to a different authority.");
    }

    internal void RequireRequest(
        ReadOnlySpan<byte> expectedNetworkId,
        ulong observedUnixTime,
        uint uncertaintySeconds,
        ulong issuedAt,
        ulong expiresAt)
    {
        if (!CryptographicOperations.FixedTimeEquals(networkId, expectedNetworkId) ||
            observedUnixTime < uncertaintySeconds ||
            observedUnixTime > ulong.MaxValue - uncertaintySeconds)
            throw new CryptographicException("The DTT1 issuance epoch does not bind the request.");
        var lower = observedUnixTime - uncertaintySeconds;
        var upper = observedUnixTime + uncertaintySeconds;
        if (lower < ValidFrom || upper > ValidUntil || issuedAt < lower || issuedAt > upper ||
            expiresAt < upper || expiresAt > ValidUntil)
            throw new CryptographicException("The DTT1 request lies outside its issuance epoch.");
    }
}
