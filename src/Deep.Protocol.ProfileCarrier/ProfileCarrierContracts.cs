using System.Diagnostics;
using Deep.Protocol.DeepExtension.Membership;

namespace Deep.Protocol.DeepExtension.SelfHostedProfiles;

public static class ProfileCarrierContract
{
    public const string Identifier = "Deep.Protocol/DPF1-v1";
    public const string Status =
        "DORMANT-EXACT-CARRIER-GO / PRODUCTION-VERIFIER-NO-GO / " +
        "ACTIVATION-NO-GO";
}

public static class ProfileCarrierLimits
{
    public const int MaximumFilePayloadBytes = 48 * 1024;
    public const int MaximumComponentBytes = 16 * 1024;
    public const int MaximumComponents = 16;
    public const int RequiredNonBridgeComponents = 3;

    public static bool IsFilePayloadLengthAllowed(int length) =>
        length is >= 0 and <= MaximumFilePayloadBytes;
}

public enum ProfileCarrierError
{
    InvalidInput = 1,
    BoundsExceeded = 2,
    InvalidFraming = 3,
    VerificationRejected = 4
}

public sealed class ProfileCarrierException : Exception
{
    internal ProfileCarrierException(ProfileCarrierError error)
        : base(MessageFor(error))
    {
        Error = error;
    }

    public ProfileCarrierError Error { get; }

    private static string MessageFor(ProfileCarrierError error) =>
        error switch
        {
            ProfileCarrierError.InvalidInput =>
                "The profile carrier input is invalid.",
            ProfileCarrierError.BoundsExceeded =>
                "A profile carrier bound was exceeded.",
            ProfileCarrierError.InvalidFraming =>
                "The profile carrier framing is invalid.",
            ProfileCarrierError.VerificationRejected =>
                "P04 rejected the profile carrier.",
            _ => "The profile carrier operation failed."
        };
}

public sealed class ProfileCarrierVerificationOptions
{
    public ProfileCarrierVerificationOptions(
        ulong verificationTimeUnixSeconds,
        uint allowedClockSkewSeconds,
        ushort protocol)
    {
        if (allowedClockSkewSeconds > MembershipLimits.MaximumClockSkewSeconds ||
            protocol == 0)
        {
            throw ProfileCarrierErrors.InvalidInput();
        }

        VerificationTimeUnixSeconds = verificationTimeUnixSeconds;
        AllowedClockSkewSeconds = allowedClockSkewSeconds;
        Protocol = protocol;
    }

    public ulong VerificationTimeUnixSeconds { get; }

    public uint AllowedClockSkewSeconds { get; }

    public ushort Protocol { get; }

    public override string ToString() => nameof(ProfileCarrierVerificationOptions);
}

public sealed class ProfileCarrierAssemblyInput
{
    private readonly byte[] canonicalGenesis;
    private readonly MembershipSignature[] genesisApprovals;
    private readonly byte[] canonicalSignedDelegation;
    private readonly byte[][] canonicalSignedBridges;

    public ProfileCarrierAssemblyInput(
        ReadOnlyMemory<byte> canonicalGenesis,
        IEnumerable<MembershipSignature> genesisApprovals,
        ReadOnlyMemory<byte> canonicalSignedDelegation,
        IEnumerable<ReadOnlyMemory<byte>> canonicalSignedBridges)
    {
        this.canonicalGenesis = CopyComponent(canonicalGenesis);
        this.canonicalSignedDelegation = CopyComponent(canonicalSignedDelegation);
        this.genesisApprovals = CopyApprovals(genesisApprovals);
        this.canonicalSignedBridges = CopyBridges(canonicalSignedBridges);
    }

    internal ReadOnlySpan<byte> GenesisSpan => canonicalGenesis;

    internal IReadOnlyList<MembershipSignature> ApprovalValues => genesisApprovals;

    internal ReadOnlySpan<byte> DelegationSpan => canonicalSignedDelegation;

    internal IReadOnlyList<byte[]> BridgeValues => canonicalSignedBridges;

    public int GenesisApprovalCount => genesisApprovals.Length;

    public int BridgeCount => canonicalSignedBridges.Length;

    public override string ToString() => nameof(ProfileCarrierAssemblyInput);

    private static byte[] CopyComponent(ReadOnlyMemory<byte> value)
    {
        if (value.Length > ProfileCarrierLimits.MaximumComponentBytes)
        {
            throw ProfileCarrierErrors.Bounds();
        }
        return value.ToArray();
    }

    private static MembershipSignature[] CopyApprovals(
        IEnumerable<MembershipSignature> values)
    {
        if (values is null)
        {
            throw ProfileCarrierErrors.InvalidInput();
        }

        var result = new List<MembershipSignature>(MembershipLimits.MaximumSigners);
        foreach (var value in values)
        {
            if (value is null || result.Count == MembershipLimits.MaximumSigners)
            {
                throw ProfileCarrierErrors.Bounds();
            }
            result.Add(CopySignature(value));
        }
        return result.ToArray();
    }

    private static byte[][] CopyBridges(IEnumerable<ReadOnlyMemory<byte>> values)
    {
        if (values is null)
        {
            throw ProfileCarrierErrors.InvalidInput();
        }

        var maximum = ProfileCarrierLimits.MaximumComponents -
            ProfileCarrierLimits.RequiredNonBridgeComponents;
        var result = new List<byte[]>(maximum);
        foreach (var value in values)
        {
            if (result.Count == maximum)
            {
                throw ProfileCarrierErrors.Bounds();
            }
            result.Add(CopyComponent(value));
        }
        return result.ToArray();
    }

    internal static MembershipSignature CopySignature(MembershipSignature value) =>
        new()
        {
            SignerId = value.SignerId.ToArray(),
            Domain = value.Domain,
            Signature = value.Signature.ToArray()
        };
}

[DebuggerDisplay("{ToString(),nq}")]
public sealed class ProfileCarrierDocument
{
    private readonly byte[] filePayload;
    private readonly byte[] filePayloadSha256;

    internal ProfileCarrierDocument(
        ReadOnlySpan<byte> filePayload,
        ReadOnlySpan<byte> filePayloadSha256,
        string fingerprint,
        ushort minimumProtocol,
        ushort maximumProtocol,
        int componentCount,
        int bridgeCount)
    {
        this.filePayload = filePayload.ToArray();
        this.filePayloadSha256 = filePayloadSha256.ToArray();
        Fingerprint = fingerprint;
        MinimumProtocol = minimumProtocol;
        MaximumProtocol = maximumProtocol;
        ComponentCount = componentCount;
        BridgeCount = bridgeCount;
    }

    public ReadOnlyMemory<byte> FilePayload => filePayload.ToArray();

    public ReadOnlyMemory<byte> FilePayloadSha256 => filePayloadSha256.ToArray();

    public string Fingerprint { get; }

    public ushort MinimumProtocol { get; }

    public ushort MaximumProtocol { get; }

    public int ComponentCount { get; }

    public int BridgeCount { get; }

    public override string ToString() => "[verified-dormant-profile-carrier]";
}

internal enum ProfileComponentKind : byte
{
    CanonicalGenesis = 1,
    GenesisApprovals = 2,
    SignedDelegation = 3,
    SignedBridge = 4
}

internal sealed record ProfileComponent(ProfileComponentKind Kind, byte[] Bytes);

internal static class ProfileCarrierErrors
{
    public static ProfileCarrierException InvalidInput() =>
        new(ProfileCarrierError.InvalidInput);

    public static ProfileCarrierException Bounds() =>
        new(ProfileCarrierError.BoundsExceeded);

    public static ProfileCarrierException Framing() =>
        new(ProfileCarrierError.InvalidFraming);

    public static ProfileCarrierException Verification() =>
        new(ProfileCarrierError.VerificationRejected);
}
