using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Deep.Protocol.DeepExtension.MailboxAuthority;

/// <summary>
/// Fixed-order PMA1 binary codec. The header (PMA1, version 1, three zero reserved bytes) is the
/// explicit schema/version. There are no extension fields: trailing bytes, unknown enum values,
/// duplicate list entries and non-canonical URI text are rejected.
/// </summary>
public static class ProductionMailboxAuthorityCodec
{
    private static ReadOnlySpan<byte> Magic => "PMA1"u8;
    private static ReadOnlySpan<byte> RevocationBindingMagic => "PMB1"u8;

    public static byte[] GetPayloadBytes(ProductionMailboxAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ValidateCore(authority);
        var writer = new Writer();
        WriteHeader(writer);
        WritePayload(writer, authority);
        return writer.ToArray();
    }

    public static byte[] GetSigningBytes(ProductionMailboxAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);
        Validate(authority, validateSignature: false);
        var writer = new Writer();
        WriteHeader(writer);
        WritePayload(writer, authority);
        WriteApproval(writer, authority.MrXApproval);
        return writer.ToArray();
    }

    public static byte[] Encode(ProductionMailboxAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);
        Validate(authority, validateSignature: true);
        var writer = new Writer();
        WriteHeader(writer);
        WritePayload(writer, authority);
        WriteApproval(writer, authority.MrXApproval);
        writer.Fixed(authority.Signature.Span, ProductionMailboxAuthorityConstants.Ed25519SignatureLength, "signature");
        return writer.ToArray();
    }

    public static ProductionMailboxAuthority Decode(ReadOnlySpan<byte> encoded)
    {
        var reader = new Reader(encoded);
        reader.Magic(Magic);
        if (reader.Byte() != ProductionMailboxAuthorityConstants.Version)
            throw Error(ProductionMailboxAuthorityError.UnsupportedVersion, "Unsupported production mailbox authority version.");
        reader.Zero(3);
        var authority = new ProductionMailboxAuthority
        {
            DevelopmentOnly = reader.Bool(),
            Environment = (ProductionMailboxAuthorityEnvironment)reader.Byte(),
            Transport = (ProductionMailboxAuthorityTransport)reader.Byte(),
            Ownership = (ProductionMailboxAuthorityOwnership)reader.Byte(),
            EndpointPolicy = (ProductionMailboxAuthorityEndpointPolicy)reader.Byte(),
            NetworkId = reader.Fixed(ProductionMailboxAuthorityConstants.NetworkIdLength),
            AuthorityGeneration = reader.UInt64(),
            PreviousAuthorityHash = reader.Fixed(ProductionMailboxAuthorityConstants.HashLength),
            MailboxIssuerEd25519PublicKey = reader.Fixed(ProductionMailboxAuthorityConstants.Ed25519PublicKeyLength),
            MrXApprovalEd25519PublicKey = reader.Fixed(ProductionMailboxAuthorityConstants.Ed25519PublicKeyLength),
            Coordinator = ReadEndpoint(ref reader),
            NodeIngress = ReadEndpoint(ref reader),
            CurrentEpoch = ReadEpoch(ref reader),
            NextEpoch = ReadEpoch(ref reader),
            Revocation = new ProductionMailboxAuthorityRevocation
            {
                SnapshotHash = reader.Fixed(ProductionMailboxAuthorityConstants.HashLength),
                HeadHash = reader.Fixed(ProductionMailboxAuthorityConstants.HashLength),
                PreviousHeadHash = reader.Fixed(ProductionMailboxAuthorityConstants.HashLength),
                Generation = reader.UInt64(),
                IssuedAtUnixSeconds = reader.UInt64(),
                ExpiresAtUnixSeconds = reader.UInt64()
            },
            MrXApproval = ReadApproval(ref reader),
            Signature = reader.Fixed(ProductionMailboxAuthorityConstants.Ed25519SignatureLength)
        };
        reader.End();
        Validate(authority, validateSignature: true);
        if (!encoded.SequenceEqual(Encode(authority)))
            throw Error(ProductionMailboxAuthorityError.NonCanonical, "Authority encoding is not canonical.");
        return authority;
    }

    public static byte[] ComputePayloadHash(ProductionMailboxAuthority authority) =>
        SHA256.HashData(GetPayloadBytes(authority));

    public static byte[] ComputeCanonicalHash(ProductionMailboxAuthority authority) =>
        SHA256.HashData(Encode(authority));

    /// <summary>
    /// Canonical pre-approval binding for PMR1. It binds every PMA1 policy field except the
    /// circular revocation SnapshotHash, approval AuthorityPayloadHash, and detached signature.
    /// Those three values may be non-zero placeholders while this hash is computed.
    /// </summary>
    public static byte[] GetRevocationBindingBytes(ProductionMailboxAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ValidateCore(authority);
        ValidateHashList(authority.MrXApproval.AllowedAndroidSigningCertificateSha256, "Android signing certificate hashes");
        ValidateHashList(authority.MrXApproval.AllowedWindowsSigningCertificateSha256, "Windows signing certificate hashes");
        ValidateHashList(authority.MrXApproval.AndroidReleaseBuildArtifactSha256, "Android release build artifact hashes");
        ValidateHashList(authority.MrXApproval.WindowsReleaseBuildArtifactSha256, "Windows release build artifact hashes");
        if (authority.MrXApproval.RolloutNotBeforeUnixSeconds == 0 ||
            authority.MrXApproval.RolloutNotBeforeUnixSeconds >= authority.MrXApproval.RolloutNotAfterUnixSeconds ||
            authority.MrXApproval.RolloutNotBeforeUnixSeconds < authority.CurrentEpoch.NotBeforeUnixSeconds ||
            authority.MrXApproval.RolloutNotAfterUnixSeconds > authority.NextEpoch.NotAfterUnixSeconds)
            throw Error(ProductionMailboxAuthorityError.InvalidValidityWindow, "Mr. X rollout window is invalid.");

        var writer = new Writer();
        writer.Bytes(RevocationBindingMagic);
        writer.Byte(ProductionMailboxAuthorityConstants.Version);
        writer.Zero(3);
        writer.Bool(authority.DevelopmentOnly);
        writer.Byte((byte)authority.Environment);
        writer.Byte((byte)authority.Transport);
        writer.Byte((byte)authority.Ownership);
        writer.Byte((byte)authority.EndpointPolicy);
        writer.Fixed(authority.NetworkId.Span, ProductionMailboxAuthorityConstants.NetworkIdLength, "network ID");
        writer.UInt64(authority.AuthorityGeneration);
        writer.Fixed(authority.PreviousAuthorityHash.Span, ProductionMailboxAuthorityConstants.HashLength, "previous authority hash");
        writer.Fixed(authority.MailboxIssuerEd25519PublicKey.Span, ProductionMailboxAuthorityConstants.Ed25519PublicKeyLength, "mailbox issuer key");
        writer.Fixed(authority.MrXApprovalEd25519PublicKey.Span, ProductionMailboxAuthorityConstants.Ed25519PublicKeyLength, "Mr. X approval key");
        WriteEndpoint(writer, authority.Coordinator);
        WriteEndpoint(writer, authority.NodeIngress);
        WriteEpoch(writer, authority.CurrentEpoch);
        WriteEpoch(writer, authority.NextEpoch);
        writer.Fixed(authority.Revocation.HeadHash.Span, ProductionMailboxAuthorityConstants.HashLength, "revocation head hash");
        writer.Fixed(authority.Revocation.PreviousHeadHash.Span, ProductionMailboxAuthorityConstants.HashLength, "previous revocation head hash");
        writer.UInt64(authority.Revocation.Generation);
        writer.UInt64(authority.Revocation.IssuedAtUnixSeconds);
        writer.UInt64(authority.Revocation.ExpiresAtUnixSeconds);
        WriteHashes(writer, authority.MrXApproval.AllowedAndroidSigningCertificateSha256, "Android signing certificate hash");
        WriteHashes(writer, authority.MrXApproval.AllowedWindowsSigningCertificateSha256, "Windows signing certificate hash");
        WriteHashes(writer, authority.MrXApproval.AndroidReleaseBuildArtifactSha256, "Android release build artifact hash");
        WriteHashes(writer, authority.MrXApproval.WindowsReleaseBuildArtifactSha256, "Windows release build artifact hash");
        writer.UInt64(authority.MrXApproval.RolloutNotBeforeUnixSeconds);
        writer.UInt64(authority.MrXApproval.RolloutNotAfterUnixSeconds);
        return writer.ToArray();
    }

    public static byte[] ComputeRevocationBindingHash(ProductionMailboxAuthority authority) =>
        SHA256.HashData(GetRevocationBindingBytes(authority));

    private static void WriteHeader(Writer writer)
    {
        writer.Bytes(Magic);
        writer.Byte(ProductionMailboxAuthorityConstants.Version);
        writer.Zero(3);
    }

    private static void WritePayload(Writer writer, ProductionMailboxAuthority value)
    {
        writer.Bool(value.DevelopmentOnly);
        writer.Byte((byte)value.Environment);
        writer.Byte((byte)value.Transport);
        writer.Byte((byte)value.Ownership);
        writer.Byte((byte)value.EndpointPolicy);
        writer.Fixed(value.NetworkId.Span, ProductionMailboxAuthorityConstants.NetworkIdLength, "network ID");
        writer.UInt64(value.AuthorityGeneration);
        writer.Fixed(value.PreviousAuthorityHash.Span, ProductionMailboxAuthorityConstants.HashLength, "previous authority hash");
        writer.Fixed(value.MailboxIssuerEd25519PublicKey.Span, ProductionMailboxAuthorityConstants.Ed25519PublicKeyLength, "mailbox issuer key");
        writer.Fixed(value.MrXApprovalEd25519PublicKey.Span, ProductionMailboxAuthorityConstants.Ed25519PublicKeyLength, "Mr. X approval key");
        WriteEndpoint(writer, value.Coordinator);
        WriteEndpoint(writer, value.NodeIngress);
        WriteEpoch(writer, value.CurrentEpoch);
        WriteEpoch(writer, value.NextEpoch);
        writer.Fixed(value.Revocation.SnapshotHash.Span, ProductionMailboxAuthorityConstants.HashLength, "revocation snapshot hash");
        writer.Fixed(value.Revocation.HeadHash.Span, ProductionMailboxAuthorityConstants.HashLength, "revocation head hash");
        writer.Fixed(value.Revocation.PreviousHeadHash.Span, ProductionMailboxAuthorityConstants.HashLength, "previous revocation head hash");
        writer.UInt64(value.Revocation.Generation);
        writer.UInt64(value.Revocation.IssuedAtUnixSeconds);
        writer.UInt64(value.Revocation.ExpiresAtUnixSeconds);
    }

    private static void WriteEndpoint(Writer writer, ProductionMailboxAuthorityEndpoint endpoint)
    {
        writer.String(CanonicalUri(endpoint.Uri));
        writer.Fixed(endpoint.CurrentSpkiSha256.Span, ProductionMailboxAuthorityConstants.HashLength, "current SPKI hash");
        writer.Fixed(endpoint.NextSpkiSha256.Span, ProductionMailboxAuthorityConstants.HashLength, "next SPKI hash");
    }

    private static ProductionMailboxAuthorityEndpoint ReadEndpoint(ref Reader reader) => new()
    {
        Uri = reader.String(ProductionMailboxAuthorityConstants.MaximumEndpointLength),
        CurrentSpkiSha256 = reader.Fixed(ProductionMailboxAuthorityConstants.HashLength),
        NextSpkiSha256 = reader.Fixed(ProductionMailboxAuthorityConstants.HashLength)
    };

    private static void WriteEpoch(Writer writer, ProductionMailboxAuthorityEpoch epoch)
    {
        writer.UInt64(epoch.Epoch);
        writer.UInt64(epoch.Generation);
        writer.Fixed(epoch.MembershipCommitment.Span, ProductionMailboxAuthorityConstants.HashLength, "membership commitment");
        writer.Fixed(epoch.TopologyPlacementCommitment.Span, ProductionMailboxAuthorityConstants.HashLength, "topology placement commitment");
        writer.UInt64(epoch.NotBeforeUnixSeconds);
        writer.UInt64(epoch.NotAfterUnixSeconds);
    }

    private static ProductionMailboxAuthorityEpoch ReadEpoch(ref Reader reader) => new()
    {
        Epoch = reader.UInt64(),
        Generation = reader.UInt64(),
        MembershipCommitment = reader.Fixed(ProductionMailboxAuthorityConstants.HashLength),
        TopologyPlacementCommitment = reader.Fixed(ProductionMailboxAuthorityConstants.HashLength),
        NotBeforeUnixSeconds = reader.UInt64(),
        NotAfterUnixSeconds = reader.UInt64()
    };

    private static void WriteApproval(Writer writer, ProductionMailboxAuthorityApproval approval)
    {
        writer.Fixed(approval.AuthorityPayloadHash.Span, ProductionMailboxAuthorityConstants.HashLength, "authority payload hash");
        WriteHashes(writer, approval.AllowedAndroidSigningCertificateSha256, "Android signing certificate hash");
        WriteHashes(writer, approval.AllowedWindowsSigningCertificateSha256, "Windows signing certificate hash");
        WriteHashes(writer, approval.AndroidReleaseBuildArtifactSha256, "Android release build artifact hash");
        WriteHashes(writer, approval.WindowsReleaseBuildArtifactSha256, "Windows release build artifact hash");
        writer.UInt64(approval.RolloutNotBeforeUnixSeconds);
        writer.UInt64(approval.RolloutNotAfterUnixSeconds);
    }

    private static ProductionMailboxAuthorityApproval ReadApproval(ref Reader reader) => new()
    {
        AuthorityPayloadHash = reader.Fixed(ProductionMailboxAuthorityConstants.HashLength),
        AllowedAndroidSigningCertificateSha256 = ReadHashes(ref reader),
        AllowedWindowsSigningCertificateSha256 = ReadHashes(ref reader),
        AndroidReleaseBuildArtifactSha256 = ReadHashes(ref reader),
        WindowsReleaseBuildArtifactSha256 = ReadHashes(ref reader),
        RolloutNotBeforeUnixSeconds = reader.UInt64(),
        RolloutNotAfterUnixSeconds = reader.UInt64()
    };

    private static void WriteHashes(Writer writer, IReadOnlyList<ReadOnlyMemory<byte>> values, string name)
    {
        if (values is null || values.Count is 0 or > ProductionMailboxAuthorityConstants.MaximumHashesPerPlatform)
            throw Error(ProductionMailboxAuthorityError.InvalidField, $"{name} count is outside bounds.");
        writer.Byte(checked((byte)values.Count));
        foreach (var value in values)
            writer.Fixed(value.Span, ProductionMailboxAuthorityConstants.HashLength, name);
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>> ReadHashes(ref Reader reader)
    {
        var count = reader.Byte();
        if (count is 0 or > ProductionMailboxAuthorityConstants.MaximumHashesPerPlatform)
            throw Error(ProductionMailboxAuthorityError.InvalidLength, "Hash list count is outside bounds.");
        var result = new ReadOnlyMemory<byte>[count];
        for (var index = 0; index < count; index++)
            result[index] = reader.Fixed(ProductionMailboxAuthorityConstants.HashLength);
        return result;
    }

    private static void Validate(ProductionMailboxAuthority value, bool validateSignature)
    {
        ValidateCore(value);
        ValidateApproval(value);
        if (validateSignature)
            Require(value.Signature, ProductionMailboxAuthorityConstants.Ed25519SignatureLength, "signature");
    }

    private static void ValidateCore(ProductionMailboxAuthority value)
    {
        if (value.Coordinator is null || value.NodeIngress is null || value.CurrentEpoch is null ||
            value.NextEpoch is null || value.Revocation is null || value.MrXApproval is null)
            throw Error(ProductionMailboxAuthorityError.InvalidField, "Authority is incomplete.");
        if (value.DevelopmentOnly || value.Environment != ProductionMailboxAuthorityEnvironment.Production ||
            value.Transport != ProductionMailboxAuthorityTransport.AuthenticatedMau2)
            throw Error(ProductionMailboxAuthorityError.InvalidField, "Only production authenticated MAU2 authority is accepted.");
        if (value.Ownership is not (ProductionMailboxAuthorityOwnership.OfficialManaged or ProductionMailboxAuthorityOwnership.UserManaged) ||
            value.EndpointPolicy is not (ProductionMailboxAuthorityEndpointPolicy.PublicHttpsOnly or ProductionMailboxAuthorityEndpointPolicy.UserManagedPrivateHttps))
            throw Error(ProductionMailboxAuthorityError.InvalidEnum, "Authority ownership or endpoint policy is invalid.");
        if (value.Ownership == ProductionMailboxAuthorityOwnership.OfficialManaged &&
            value.EndpointPolicy != ProductionMailboxAuthorityEndpointPolicy.PublicHttpsOnly)
            throw Error(ProductionMailboxAuthorityError.InvalidEndpoint, "Official managed authority must use public HTTPS endpoints.");
        Require(value.NetworkId, ProductionMailboxAuthorityConstants.NetworkIdLength, "network ID");
        Require(value.PreviousAuthorityHash, ProductionMailboxAuthorityConstants.HashLength, "previous authority hash");
        Require(value.MailboxIssuerEd25519PublicKey, ProductionMailboxAuthorityConstants.Ed25519PublicKeyLength, "mailbox issuer public key");
        Require(value.MrXApprovalEd25519PublicKey, ProductionMailboxAuthorityConstants.Ed25519PublicKeyLength, "Mr. X approval public key");
        if (CryptographicOperations.FixedTimeEquals(value.MailboxIssuerEd25519PublicKey.Span, value.MrXApprovalEd25519PublicKey.Span))
            throw Error(ProductionMailboxAuthorityError.InvalidField, "Mailbox issuer and Mr. X approval keys must be distinct roles.");
        if (value.AuthorityGeneration == 0)
            throw Error(ProductionMailboxAuthorityError.InvalidField, "Authority generation must be non-zero.");
        ValidateEndpoint(value.Coordinator, value.Ownership, value.EndpointPolicy);
        ValidateEndpoint(value.NodeIngress, value.Ownership, value.EndpointPolicy);
        if (EndpointOrigin(value.Coordinator.Uri).Equals(EndpointOrigin(value.NodeIngress.Uri), StringComparison.Ordinal))
            throw Error(ProductionMailboxAuthorityError.InvalidEndpoint, "Coordinator and node ingress origins must be distinct.");
        ValidateEpoch(value.CurrentEpoch, "current");
        ValidateEpoch(value.NextEpoch, "next");
        if (value.NextEpoch.Epoch <= value.CurrentEpoch.Epoch || value.NextEpoch.Generation <= value.CurrentEpoch.Generation ||
            value.NextEpoch.NotBeforeUnixSeconds > value.CurrentEpoch.NotAfterUnixSeconds)
            throw Error(ProductionMailboxAuthorityError.InvalidEpochOrder, "Next epoch must advance and overlap the current epoch.");
        Require(value.Revocation.SnapshotHash, ProductionMailboxAuthorityConstants.HashLength, "revocation snapshot hash");
        Require(value.Revocation.HeadHash, ProductionMailboxAuthorityConstants.HashLength, "revocation head hash");
        Require(value.Revocation.PreviousHeadHash, ProductionMailboxAuthorityConstants.HashLength, "previous revocation head hash");
        if (value.Revocation.Generation == 0 || value.Revocation.IssuedAtUnixSeconds == 0 ||
            value.Revocation.IssuedAtUnixSeconds >= value.Revocation.ExpiresAtUnixSeconds ||
            value.Revocation.ExpiresAtUnixSeconds - value.Revocation.IssuedAtUnixSeconds > ProductionMailboxAuthorityConstants.MaximumRevocationSnapshotLifetimeSeconds ||
            CryptographicOperations.FixedTimeEquals(value.Revocation.HeadHash.Span, value.Revocation.PreviousHeadHash.Span))
            throw Error(ProductionMailboxAuthorityError.InvalidValidityWindow, "Revocation state is incomplete, non-monotonic or too long-lived.");
    }

    private static void ValidateApproval(ProductionMailboxAuthority value)
    {
        var approval = value.MrXApproval;
        Require(approval.AuthorityPayloadHash, ProductionMailboxAuthorityConstants.HashLength, "approval payload hash");
        ValidateHashList(approval.AllowedAndroidSigningCertificateSha256, "Android signing certificate hashes");
        ValidateHashList(approval.AllowedWindowsSigningCertificateSha256, "Windows signing certificate hashes");
        ValidateHashList(approval.AndroidReleaseBuildArtifactSha256, "Android release build artifact hashes");
        ValidateHashList(approval.WindowsReleaseBuildArtifactSha256, "Windows release build artifact hashes");
        if (approval.RolloutNotBeforeUnixSeconds == 0 || approval.RolloutNotBeforeUnixSeconds >= approval.RolloutNotAfterUnixSeconds ||
            approval.RolloutNotBeforeUnixSeconds < value.CurrentEpoch.NotBeforeUnixSeconds ||
            approval.RolloutNotAfterUnixSeconds > value.NextEpoch.NotAfterUnixSeconds)
            throw Error(ProductionMailboxAuthorityError.InvalidValidityWindow, "Mr. X rollout window is invalid.");
        if (!CryptographicOperations.FixedTimeEquals(approval.AuthorityPayloadHash.Span, SHA256.HashData(GetPayloadBytes(value))))
            throw Error(ProductionMailboxAuthorityError.InvalidApprovalBinding, "Mr. X approval payload hash does not bind this authority payload.");
    }

    private static void ValidateHashList(IReadOnlyList<ReadOnlyMemory<byte>> values, string name)
    {
        if (values is null || values.Count is 0 or > ProductionMailboxAuthorityConstants.MaximumHashesPerPlatform)
            throw Error(ProductionMailboxAuthorityError.InvalidField, $"{name} count is outside bounds.");
        byte[]? previous = null;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var value in values)
        {
            Require(value, ProductionMailboxAuthorityConstants.HashLength, name);
            if (previous is not null && previous.AsSpan().SequenceCompareTo(value.Span) >= 0)
                throw Error(ProductionMailboxAuthorityError.NonCanonical, $"{name} must be strictly lexicographically ordered.");
            if (!seen.Add(Convert.ToHexString(value.Span)))
                throw Error(ProductionMailboxAuthorityError.InvalidField, $"{name} must be distinct.");
            previous = value.ToArray();
        }
    }

    private static void ValidateEpoch(ProductionMailboxAuthorityEpoch value, string name)
    {
        Require(value.MembershipCommitment, ProductionMailboxAuthorityConstants.HashLength, $"{name} membership commitment");
        Require(value.TopologyPlacementCommitment, ProductionMailboxAuthorityConstants.HashLength, $"{name} topology placement commitment");
        if (value.Epoch == 0 || value.Generation == 0 || value.NotBeforeUnixSeconds == 0 ||
            value.NotBeforeUnixSeconds >= value.NotAfterUnixSeconds)
            throw Error(ProductionMailboxAuthorityError.InvalidValidityWindow, $"{name} epoch validity is invalid.");
    }

    private static void ValidateEndpoint(ProductionMailboxAuthorityEndpoint endpoint, ProductionMailboxAuthorityOwnership ownership, ProductionMailboxAuthorityEndpointPolicy policy)
    {
        if (endpoint is null)
            throw Error(ProductionMailboxAuthorityError.InvalidEndpoint, "Endpoint is missing.");
        var uri = ParseCanonicalUri(endpoint.Uri);
        if (uri.Scheme != Uri.UriSchemeHttps || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0 ||
            uri.Port is <= 0 or > 65535 || HasDevelopmentMarker(uri.Host))
            throw Error(ProductionMailboxAuthorityError.InvalidEndpoint, "Endpoint must be canonical production HTTPS without a development marker.");
        var isPrivate = IsLoopbackOrPrivate(uri.Host);
        if (isPrivate && !(ownership == ProductionMailboxAuthorityOwnership.UserManaged && policy == ProductionMailboxAuthorityEndpointPolicy.UserManagedPrivateHttps))
            throw Error(ProductionMailboxAuthorityError.InvalidEndpoint, "Private or loopback endpoints require explicit user-managed private HTTPS policy.");
        Require(endpoint.CurrentSpkiSha256, ProductionMailboxAuthorityConstants.HashLength, "current SPKI hash");
        Require(endpoint.NextSpkiSha256, ProductionMailboxAuthorityConstants.HashLength, "next SPKI hash");
        if (CryptographicOperations.FixedTimeEquals(endpoint.CurrentSpkiSha256.Span, endpoint.NextSpkiSha256.Span))
            throw Error(ProductionMailboxAuthorityError.InvalidPinSet, "Current and next SPKI pins must be distinct.");
    }

    private static void Require(ReadOnlyMemory<byte> value, int length, string name)
    {
        if (value.Length != length || value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw Error(ProductionMailboxAuthorityError.InvalidField, $"{name} is invalid or all-zero.");
    }

    private static string CanonicalUri(string value) => ParseCanonicalUri(value).AbsoluteUri;

    private static Uri ParseCanonicalUri(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > ProductionMailboxAuthorityConstants.MaximumEndpointLength ||
            !Uri.TryCreate(value, UriKind.Absolute, out var uri) || !StringComparer.Ordinal.Equals(value, uri.AbsoluteUri))
            throw Error(ProductionMailboxAuthorityError.InvalidEndpoint, "Endpoint URI is not absolute canonical text.");
        return uri;
    }

    private static string EndpointOrigin(string value)
    {
        var uri = ParseCanonicalUri(value);
        return uri.GetComponents(UriComponents.SchemeAndServer, UriFormat.UriEscaped);
    }

    private static bool HasDevelopmentMarker(string host)
    {
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith(".local", StringComparison.OrdinalIgnoreCase) || host.EndsWith(".test", StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith(".invalid", StringComparison.OrdinalIgnoreCase))
            return true;
        return host.Split('.').Any(static label => label.Equals("dev", StringComparison.OrdinalIgnoreCase) ||
            label.Equals("lab", StringComparison.OrdinalIgnoreCase) || label.Equals("test", StringComparison.OrdinalIgnoreCase) ||
            label.Equals("staging", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsLoopbackOrPrivate(string host)
    {
        if (!IPAddress.TryParse(host, out var address))
            return false;
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
            return true;
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var ipv6 = address.GetAddressBytes();
            // Unique-local fc00::/7, link-local fe80::/10, multicast and documentation/reserved space.
            return (ipv6[0] & 0xfe) == 0xfc || (ipv6[0] == 0xfe && (ipv6[1] & 0xc0) == 0x80) ||
                ipv6[0] == 0xff || (ipv6[0] == 0x20 && ipv6[1] == 0x01 && ipv6[2] == 0x0d && ipv6[3] == 0xb8);
        }
        var bytes = address.MapToIPv4().GetAddressBytes();
        return bytes[0] == 10 || bytes[0] == 127 || (bytes[0] == 169 && bytes[1] == 254) ||
            (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) || (bytes[0] == 192 && bytes[1] == 168) ||
            bytes[0] == 0 || bytes[0] >= 224;
    }

    private static ProductionMailboxAuthorityException Error(ProductionMailboxAuthorityError error, string message) => new(error, message);

    private sealed class Writer
    {
        private readonly List<byte> _bytes = [];
        public void Byte(byte value) => _bytes.Add(value);
        public void Bool(bool value) => Byte(value ? (byte)1 : (byte)0);
        public void UInt64(ulong value)
        {
            Span<byte> bytes = stackalloc byte[sizeof(ulong)];
            BinaryPrimitives.WriteUInt64LittleEndian(bytes, value);
            Bytes(bytes);
        }
        public void Zero(int count) { for (var index = 0; index < count; index++) _bytes.Add(0); }
        public void Bytes(ReadOnlySpan<byte> value) { foreach (var item in value) _bytes.Add(item); }
        public void Fixed(ReadOnlySpan<byte> value, int length, string name)
        {
            if (value.Length != length) throw Error(ProductionMailboxAuthorityError.InvalidLength, $"{name} length is invalid.");
            Bytes(value);
        }
        public void String(string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            if (bytes.Length == 0 || bytes.Length > ProductionMailboxAuthorityConstants.MaximumEndpointLength)
                throw Error(ProductionMailboxAuthorityError.InvalidLength, "Endpoint string length is invalid.");
            _bytes.Add(checked((byte)bytes.Length));
            Bytes(bytes);
        }
        public byte[] ToArray() => _bytes.ToArray();
    }

    private ref struct Reader(ReadOnlySpan<byte> source)
    {
        private ReadOnlySpan<byte> _remaining = source;
        public byte Byte()
        {
            if (_remaining.IsEmpty) throw Error(ProductionMailboxAuthorityError.InvalidLength, "Unexpected end of authority.");
            var result = _remaining[0]; _remaining = _remaining[1..]; return result;
        }
        public bool Bool()
        {
            var value = Byte();
            return value switch { 0 => false, 1 => true, _ => throw Error(ProductionMailboxAuthorityError.InvalidField, "Boolean is not canonical.") };
        }
        public ulong UInt64()
        {
            var value = Fixed(sizeof(ulong));
            return BinaryPrimitives.ReadUInt64LittleEndian(value.Span);
        }
        public ReadOnlyMemory<byte> Fixed(int count)
        {
            if (count < 0 || _remaining.Length < count) throw Error(ProductionMailboxAuthorityError.InvalidLength, "Unexpected end of authority.");
            var result = _remaining[..count].ToArray(); _remaining = _remaining[count..]; return result;
        }
        public string String(int maximum)
        {
            var count = Byte();
            if (count == 0 || count > maximum) throw Error(ProductionMailboxAuthorityError.InvalidLength, "String length is invalid.");
            try { return new UTF8Encoding(false, true).GetString(Fixed(count).Span); }
            catch (DecoderFallbackException) { throw Error(ProductionMailboxAuthorityError.InvalidField, "String is not valid UTF-8."); }
        }
        public void Magic(ReadOnlySpan<byte> magic)
        {
            if (!Fixed(magic.Length).Span.SequenceEqual(magic)) throw Error(ProductionMailboxAuthorityError.InvalidMagic, "Authority magic is invalid.");
        }
        public void Zero(int count)
        {
            if (Fixed(count).Span.IndexOfAnyExcept((byte)0) >= 0) throw Error(ProductionMailboxAuthorityError.ReservedFieldNotZero, "Reserved authority field is non-zero.");
        }
        public void End()
        {
            if (!_remaining.IsEmpty) throw Error(ProductionMailboxAuthorityError.NonCanonical, "Authority has trailing bytes.");
        }
    }
}
