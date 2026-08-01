using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

/// <summary>Strict fixed-order PMT1 and PMS1 codecs. No private-key or signing API is exposed.</summary>
public static class ProductionMailboxTopologyCodec
{
    private static ReadOnlySpan<byte> TopologyMagic => "PMT1"u8;
    private static ReadOnlySpan<byte> SelectionMagic => "PMS1"u8;

    public static byte[] GetSigningBytes(ProductionMailboxTopologySnapshot value)
    {
        Validate(value, false);
        var writer = new Writer();
        WriteTopology(writer, value, false);
        return writer.ToArray();
    }

    public static byte[] Encode(ProductionMailboxTopologySnapshot value)
    {
        Validate(value, true);
        var writer = new Writer();
        WriteTopology(writer, value, true);
        return writer.ToArray();
    }

    public static ProductionMailboxTopologySnapshot Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length > ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes)
            throw Error(ProductionMailboxTopologyError.InvalidLength, "PMT1 exceeds its strict maximum length.");
        var reader = new Reader(encoded);
        reader.Magic(TopologyMagic);
        Version(ref reader);
        var value = new ProductionMailboxTopologySnapshot
        {
            NetworkId = reader.Fixed(ProductionMailboxTopologyConstants.NetworkIdLength),
            AuthorityGeneration = reader.UInt64(),
            CanonicalAuthorityHash = reader.Fixed(32),
            TopologyGeneration = reader.UInt64(),
            PreviousTopologyHash = reader.Fixed(32),
            IssuedAtUnixSeconds = reader.UInt64(),
            ExpiresAtUnixSeconds = reader.UInt64(),
            CurrentEpoch = ReadEpoch(ref reader),
            NextEpoch = ReadEpoch(ref reader),
            IssuerSignature = reader.Fixed(64)
        };
        reader.End();
        Validate(value, true);
        if (!encoded.SequenceEqual(Encode(value)))
            throw Error(ProductionMailboxTopologyError.NonCanonical, "PMT1 is not canonical.");
        return value;
    }

    public static byte[] ComputeCanonicalHash(ProductionMailboxTopologySnapshot value) => SHA256.HashData(Encode(value));

    public static byte[] GetSelectionSigningBytes(ProductionMailboxSelectionProof value)
    {
        Validate(value, false);
        var writer = new Writer();
        WriteSelection(writer, value, false);
        return writer.ToArray();
    }

    public static byte[] EncodeSelection(ProductionMailboxSelectionProof value)
    {
        Validate(value, true);
        var writer = new Writer();
        WriteSelection(writer, value, true);
        return writer.ToArray();
    }

    public static ProductionMailboxSelectionProof DecodeSelection(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes)
            throw Error(ProductionMailboxTopologyError.InvalidLength, "PMS1 exceeds its strict maximum length.");
        var reader = new Reader(encoded);
        reader.Magic(SelectionMagic);
        Version(ref reader);
        var algorithm = (ProductionMailboxSelectionAlgorithm)reader.Byte();
        reader.Zero(3);
        var network = reader.Fixed(16);
        var authorityGeneration = reader.UInt64();
        var authorityHash = reader.Fixed(32);
        var topologyGeneration = reader.UInt64();
        var topologyHash = reader.Fixed(32);
        var epoch = reader.UInt64();
        var generation = reader.UInt64();
        var membership = reader.Fixed(32);
        var placement = reader.Fixed(32);
        var selectionInput = reader.Fixed(32);
        var issued = reader.UInt64();
        var expires = reader.UInt64();
        var count = reader.Byte();
        reader.Zero(3);
        if (count != ProductionMailboxTopologyConstants.ReplicaCount)
            throw Error(ProductionMailboxTopologyError.InvalidField, "PMS1 must contain exactly two replicas.");
        var replicas = new ProductionMailboxSelectionReplica[count];
        for (var i = 0; i < replicas.Length; i++)
        {
            var id = reader.Fixed(32);
            var proofLength = reader.UInt16();
            reader.Zero(2);
            replicas[i] = new ProductionMailboxSelectionReplica
            {
                ReplicaId = id,
                CanonicalMIP1Proof = reader.Fixed(proofLength)
            };
        }
        var value = new ProductionMailboxSelectionProof
        {
            Algorithm = algorithm,
            NetworkId = network,
            AuthorityGeneration = authorityGeneration,
            CanonicalAuthorityHash = authorityHash,
            TopologyGeneration = topologyGeneration,
            CanonicalTopologyHash = topologyHash,
            Epoch = epoch,
            Generation = generation,
            MembershipCommitment = membership,
            PlacementCommitment = placement,
            SelectionInputCommitment = selectionInput,
            IssuedAtUnixSeconds = issued,
            ExpiresAtUnixSeconds = expires,
            Replicas = replicas,
            IssuerSignature = reader.Fixed(64)
        };
        reader.End();
        Validate(value, true);
        if (!encoded.SequenceEqual(EncodeSelection(value)))
            throw Error(ProductionMailboxTopologyError.NonCanonical, "PMS1 is not canonical.");
        return value;
    }

    public static byte[] ComputeSelectionCanonicalHash(ProductionMailboxSelectionProof value) =>
        SHA256.HashData(EncodeSelection(value));

    private static void WriteTopology(Writer writer, ProductionMailboxTopologySnapshot value, bool signature)
    {
        writer.Fixed(TopologyMagic, 4, "magic"); Header(writer);
        writer.Fixed(value.NetworkId.Span, 16, "network id"); writer.UInt64(value.AuthorityGeneration);
        writer.Fixed(value.CanonicalAuthorityHash.Span, 32, "authority hash"); writer.UInt64(value.TopologyGeneration);
        writer.Fixed(value.PreviousTopologyHash.Span, 32, "previous topology hash");
        writer.UInt64(value.IssuedAtUnixSeconds); writer.UInt64(value.ExpiresAtUnixSeconds);
        WriteEpoch(writer, value.CurrentEpoch); WriteEpoch(writer, value.NextEpoch);
        if (signature) writer.Fixed(value.IssuerSignature.Span, 64, "signature");
    }

    private static void WriteEpoch(Writer writer, ProductionMailboxTopologyEpoch value)
    {
        writer.UInt64(value.Epoch); writer.UInt64(value.Generation);
        writer.Fixed(value.MembershipCommitment.Span, 32, "membership commitment");
        writer.Fixed(value.PlacementCommitment.Span, 32, "placement commitment");
        writer.UInt64(value.NotBeforeUnixSeconds); writer.UInt64(value.NotAfterUnixSeconds);
        writer.UInt16(checked((ushort)value.Nodes.Count)); writer.Zero(2);
        foreach (var node in value.Nodes)
        {
            writer.Fixed(node.NodeId.Span, 32, "node id"); writer.String(node.HttpsEndpoint);
            writer.Fixed(node.CurrentSpkiSha256.Span, 32, "current SPKI");
            writer.Fixed(node.NextSpkiSha256.Span, 32, "next SPKI");
        }
    }

    private static ProductionMailboxTopologyEpoch ReadEpoch(ref Reader reader)
    {
        var epoch = reader.UInt64(); var generation = reader.UInt64();
        var membership = reader.Fixed(32); var placement = reader.Fixed(32);
        var from = reader.UInt64(); var until = reader.UInt64();
        var count = reader.UInt16(); reader.Zero(2);
        if (count < 2 || count > ProductionMailboxTopologyConstants.MaximumNodesPerEpoch)
            throw Error(ProductionMailboxTopologyError.InvalidField, "PMT1 node count is outside strict bounds.");
        var nodes = new ProductionMailboxTopologyNode[count];
        for (var i = 0; i < nodes.Length; i++)
            nodes[i] = new ProductionMailboxTopologyNode
            {
                NodeId = reader.Fixed(32),
                HttpsEndpoint = reader.String(),
                CurrentSpkiSha256 = reader.Fixed(32),
                NextSpkiSha256 = reader.Fixed(32)
            };
        return new ProductionMailboxTopologyEpoch
        {
            Epoch = epoch,
            Generation = generation,
            MembershipCommitment = membership,
            PlacementCommitment = placement,
            NotBeforeUnixSeconds = from,
            NotAfterUnixSeconds = until,
            Nodes = nodes
        };
    }

    private static void WriteSelection(Writer writer, ProductionMailboxSelectionProof value, bool signature)
    {
        writer.Fixed(SelectionMagic, 4, "magic"); Header(writer); writer.Byte((byte)value.Algorithm); writer.Zero(3);
        writer.Fixed(value.NetworkId.Span, 16, "network id"); writer.UInt64(value.AuthorityGeneration);
        writer.Fixed(value.CanonicalAuthorityHash.Span, 32, "authority hash"); writer.UInt64(value.TopologyGeneration);
        writer.Fixed(value.CanonicalTopologyHash.Span, 32, "topology hash"); writer.UInt64(value.Epoch);
        writer.UInt64(value.Generation); writer.Fixed(value.MembershipCommitment.Span, 32, "membership commitment");
        writer.Fixed(value.PlacementCommitment.Span, 32, "placement commitment");
        writer.Fixed(value.SelectionInputCommitment.Span, 32, "selection input");
        writer.UInt64(value.IssuedAtUnixSeconds); writer.UInt64(value.ExpiresAtUnixSeconds);
        writer.Byte(checked((byte)value.Replicas.Count)); writer.Zero(3);
        foreach (var replica in value.Replicas)
        {
            writer.Fixed(replica.ReplicaId.Span, 32, "replica id");
            writer.UInt16(checked((ushort)replica.CanonicalMIP1Proof.Length)); writer.Zero(2);
            writer.Fixed(replica.CanonicalMIP1Proof.Span, replica.CanonicalMIP1Proof.Length, "MIP1 proof");
        }
        if (signature) writer.Fixed(value.IssuerSignature.Span, 64, "signature");
    }

    private static void Validate(ProductionMailboxTopologySnapshot value, bool signature)
    {
        ArgumentNullException.ThrowIfNull(value);
        Fixed(value.NetworkId, 16, "network id"); Fixed(value.CanonicalAuthorityHash, 32, "authority hash");
        Length(value.PreviousTopologyHash, 32, "previous topology hash");
        if (value.AuthorityGeneration == 0 || value.TopologyGeneration == 0) Invalid("Generations must be non-zero.");
        if (value.TopologyGeneration == 1)
        {
            if (value.PreviousTopologyHash.Span.IndexOfAnyExcept((byte)0) >= 0)
                throw Error(ProductionMailboxTopologyError.PreviousHashMismatch, "PMT1 genesis previous hash must be zero.");
        }
        else if (value.PreviousTopologyHash.Span.IndexOfAnyExcept((byte)0) < 0)
            throw Error(ProductionMailboxTopologyError.PreviousHashMismatch, "Non-genesis PMT1 previous hash must be non-zero.");
        Window(value.IssuedAtUnixSeconds, value.ExpiresAtUnixSeconds, "topology", boundedLifetime: true);
        Epoch(value.CurrentEpoch, "current"); Epoch(value.NextEpoch, "next");
        if (value.NextEpoch.Epoch <= value.CurrentEpoch.Epoch || value.NextEpoch.Generation <= value.CurrentEpoch.Generation ||
            value.NextEpoch.NotBeforeUnixSeconds > value.CurrentEpoch.NotAfterUnixSeconds)
            throw Error(ProductionMailboxTopologyError.InvalidOrder, "PMT1 current/next epoch order or overlap is invalid.");
        if (signature) Fixed(value.IssuerSignature, 64, "signature");
    }

    private static void Epoch(ProductionMailboxTopologyEpoch value, string name)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Epoch == 0 || value.Generation == 0) Invalid($"{name} epoch/generation is invalid.");
        Fixed(value.MembershipCommitment, 32, "membership commitment"); Fixed(value.PlacementCommitment, 32, "placement commitment");
        Window(value.NotBeforeUnixSeconds, value.NotAfterUnixSeconds, name, boundedLifetime: false);
        var nodes = value.Nodes;
        if (nodes is null || nodes.Count < 2 || nodes.Count > ProductionMailboxTopologyConstants.MaximumNodesPerEpoch)
            Invalid($"{name} node count is outside strict bounds.");
        byte[]? previous = null; var endpoints = new HashSet<string>(StringComparer.Ordinal);
        foreach (var node in nodes!)
        {
            ArgumentNullException.ThrowIfNull(node); Fixed(node.NodeId, 32, "node id");
            if (previous is not null && Compare(previous, node.NodeId.Span) >= 0)
                throw Error(ProductionMailboxTopologyError.InvalidOrder, "PMT1 node IDs must be strictly increasing.");
            previous = node.NodeId.ToArray(); ValidateEndpoint(node.HttpsEndpoint);
            if (!endpoints.Add(node.HttpsEndpoint)) throw Error(ProductionMailboxTopologyError.InvalidEndpoint, "Duplicate PMT1 endpoint.");
            Fixed(node.CurrentSpkiSha256, 32, "current SPKI"); Fixed(node.NextSpkiSha256, 32, "next SPKI");
            if (CryptographicOperations.FixedTimeEquals(node.CurrentSpkiSha256.Span, node.NextSpkiSha256.Span))
                throw Error(ProductionMailboxTopologyError.InvalidPinSet, "Current and next SPKI pins must differ.");
        }
    }

    private static void Validate(ProductionMailboxSelectionProof value, bool signature)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Algorithm != ProductionMailboxSelectionAlgorithm.RendezvousSha256V1) Invalid("Unknown selection algorithm.");
        Fixed(value.NetworkId, 16, "network id"); Fixed(value.CanonicalAuthorityHash, 32, "authority hash");
        Fixed(value.CanonicalTopologyHash, 32, "topology hash"); Fixed(value.MembershipCommitment, 32, "membership commitment");
        Fixed(value.PlacementCommitment, 32, "placement commitment"); Fixed(value.SelectionInputCommitment, 32, "selection input");
        if (value.AuthorityGeneration == 0 || value.TopologyGeneration == 0 || value.Epoch == 0 || value.Generation == 0) Invalid("PMS1 generations/epoch are invalid.");
        Window(value.IssuedAtUnixSeconds, value.ExpiresAtUnixSeconds, "selection", boundedLifetime: true);
        var replicas = value.Replicas;
        if (replicas is null || replicas.Count != 2) Invalid("PMS1 must contain exactly two replicas.");
        foreach (var replica in replicas!)
        {
            ArgumentNullException.ThrowIfNull(replica); Fixed(replica.ReplicaId, 32, "replica id");
            if (replica.CanonicalMIP1Proof.Length is < MailboxPeerReplicationLimits.MembershipProofFixedLength or >
                (MailboxPeerReplicationLimits.MembershipProofFixedLength + MailboxPeerReplicationLimits.MaximumInclusionProofLength)) Invalid("MIP1 proof length is invalid.");
            MailboxReplicaMembershipProof decoded;
            try { decoded = MailboxPeerReplicationCodec.DecodeMembershipProof(replica.CanonicalMIP1Proof.Span); }
            catch (MailboxPeerReplicationException ex)
            { throw Error(ProductionMailboxTopologyError.InvalidMembershipProof, ex.Message); }
            if (!replica.CanonicalMIP1Proof.Span.SequenceEqual(MailboxPeerReplicationCodec.EncodeMembershipProof(decoded)))
                throw Error(ProductionMailboxTopologyError.NonCanonical, "Embedded MIP1 proof is not canonical.");
        }
        if (replicas![0].ReplicaId.Span.SequenceEqual(replicas[1].ReplicaId.Span)) Invalid("PMS1 replica IDs must be distinct.");
        if (signature) Fixed(value.IssuerSignature, 64, "signature");
    }

    private static void Window(ulong from, ulong until, string name, bool boundedLifetime)
    {
        if (from == 0 || from >= until ||
            (boundedLifetime && until - from > ProductionMailboxTopologyConstants.MaximumArtifactLifetimeSeconds))
            throw Error(ProductionMailboxTopologyError.InvalidValidityWindow, $"{name} validity window is invalid.");
    }

    private static void ValidateEndpoint(string text)
    {
        if (string.IsNullOrWhiteSpace(text) || Encoding.UTF8.GetByteCount(text) > ProductionMailboxTopologyConstants.MaximumEndpointBytes ||
            !Uri.TryCreate(text, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps || string.IsNullOrEmpty(uri.Host) ||
            !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment) ||
            uri.AbsolutePath != "/" || uri.AbsoluteUri != text || uri.Port is <= 0 or > 65535 ||
            HasDevelopmentMarker(uri.Host))
            throw Error(ProductionMailboxTopologyError.InvalidEndpoint, "PMT1 endpoint must be a canonical non-development HTTPS origin.");
    }

    internal static bool IsPrivateEndpoint(string text)
    {
        var uri = new Uri(text, UriKind.Absolute);
        if (!IPAddress.TryParse(uri.Host.Trim('[', ']'), out var ip)) return false;
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        var bytes = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork)
            return bytes[0] == 10 || bytes[0] == 127 || bytes[0] == 0 || (bytes[0] == 169 && bytes[1] == 254) ||
                   (bytes[0] == 100 && bytes[1] is >= 64 and <= 127) ||
                   (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) ||
                   (bytes[0] == 192 && (bytes[1] == 168 || (bytes[1] == 0 && bytes[2] is 0 or 2))) ||
                   (bytes[0] == 198 && (bytes[1] is 18 or 19 || (bytes[1] == 51 && bytes[2] == 100))) ||
                   (bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113) || bytes[0] >= 224;
        return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || bytes.All(static b => b == 0) ||
               (bytes[0] & 0xfe) == 0xfc || bytes[0] == 0xff ||
               (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8);
    }

    private static bool HasDevelopmentMarker(string host) =>
        host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
        host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase) ||
        host.EndsWith(".local", StringComparison.OrdinalIgnoreCase) ||
        host.EndsWith(".test", StringComparison.OrdinalIgnoreCase) ||
        host.EndsWith(".invalid", StringComparison.OrdinalIgnoreCase) ||
        host.Split('.').Any(static label => label.Equals("dev", StringComparison.OrdinalIgnoreCase) ||
            label.Equals("lab", StringComparison.OrdinalIgnoreCase) || label.Equals("test", StringComparison.OrdinalIgnoreCase) ||
            label.Equals("staging", StringComparison.OrdinalIgnoreCase));

    private static void Fixed(ReadOnlyMemory<byte> value, int length, string name)
    { if (value.Length != length || value.Span.IndexOfAnyExcept((byte)0) < 0) Invalid($"{name} is invalid."); }
    private static void Length(ReadOnlyMemory<byte> value, int length, string name)
    { if (value.Length != length) Invalid($"{name} length is invalid."); }
    private static int Compare(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.SequenceCompareTo(b);
    private static void Invalid(string message) => throw Error(ProductionMailboxTopologyError.InvalidField, message);
    private static ProductionMailboxTopologyException Error(ProductionMailboxTopologyError error, string message) => new(error, message);
    private static void Header(Writer writer) { writer.Byte(1); writer.Zero(3); }
    private static void Version(ref Reader reader) { if (reader.Byte() != 1) throw Error(ProductionMailboxTopologyError.UnsupportedVersion, "Unsupported version."); reader.Zero(3); }

    private sealed class Writer
    {
        private readonly MemoryStream _stream = new();
        public void Byte(byte value) => _stream.WriteByte(value);
        public void Zero(int count) => _stream.Write(new byte[count]);
        public void UInt16(ushort value) { Span<byte> b = stackalloc byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, value); _stream.Write(b); }
        public void UInt64(ulong value) { Span<byte> b = stackalloc byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, value); _stream.Write(b); }
        public void Fixed(ReadOnlySpan<byte> value, int length, string name) { if (value.Length != length) Invalid($"{name} length is invalid."); _stream.Write(value); }
        public void String(string value) { var bytes = Encoding.UTF8.GetBytes(value); UInt16(checked((ushort)bytes.Length)); Fixed(bytes, bytes.Length, "string"); }
        public byte[] ToArray() => _stream.ToArray();
    }

    private ref struct Reader
    {
        private readonly ReadOnlySpan<byte> _input; private int _offset;
        public Reader(ReadOnlySpan<byte> input) { _input = input; _offset = 0; }
        public byte Byte() { Need(1); return _input[_offset++]; }
        public ushort UInt16() { Need(2); var v = BinaryPrimitives.ReadUInt16BigEndian(_input.Slice(_offset, 2)); _offset += 2; return v; }
        public ulong UInt64() { Need(8); var v = BinaryPrimitives.ReadUInt64BigEndian(_input.Slice(_offset, 8)); _offset += 8; return v; }
        public byte[] Fixed(int length) { Need(length); var v = _input.Slice(_offset, length).ToArray(); _offset += length; return v; }
        public string String() { var length = UInt16(); if (length == 0 || length > ProductionMailboxTopologyConstants.MaximumEndpointBytes) Invalid("String length is invalid."); Need(length); try { var utf8 = new UTF8Encoding(false, true); var value = utf8.GetString(_input.Slice(_offset, length)); _offset += length; return value; } catch (DecoderFallbackException) { throw Error(ProductionMailboxTopologyError.InvalidField, "Invalid UTF-8."); } }
        public void Magic(ReadOnlySpan<byte> magic) { Need(magic.Length); if (!_input.Slice(_offset, magic.Length).SequenceEqual(magic)) throw Error(ProductionMailboxTopologyError.InvalidMagic, "Magic is invalid."); _offset += magic.Length; }
        public void Zero(int count) { Need(count); if (_input.Slice(_offset, count).IndexOfAnyExcept((byte)0) >= 0) throw Error(ProductionMailboxTopologyError.ReservedFieldNotZero, "Reserved bytes must be zero."); _offset += count; }
        public void End() { if (_offset != _input.Length) throw Error(ProductionMailboxTopologyError.InvalidLength, "Trailing bytes are forbidden."); }
        private void Need(int count) { if (count < 0 || _offset > _input.Length - count) throw Error(ProductionMailboxTopologyError.InvalidLength, "Artifact is truncated."); }
    }
}
