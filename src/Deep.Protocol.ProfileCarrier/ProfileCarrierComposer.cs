using System.Buffers;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.Membership;

namespace Deep.Protocol.DeepExtension.SelfHostedProfiles;

public static class ProfileCarrierComposer
{
    public static ProfileCarrierDocument ComposeExact(
        ProfileCarrierAssemblyInput input,
        ProfileCarrierVerificationOptions options,
        IMembershipSignatureVerifier verifier)
    {
        if (input is null || options is null || verifier is null)
        {
            throw ProfileCarrierErrors.InvalidInput();
        }

        try
        {
            return ComposeCore(input, options, verifier);
        }
        catch (ProfileCarrierException)
        {
            throw;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            throw ProfileCarrierErrors.Verification();
        }
    }

    private static ProfileCarrierDocument ComposeCore(
        ProfileCarrierAssemblyInput input,
        ProfileCarrierVerificationOptions options,
        IMembershipSignatureVerifier verifier)
    {
        var canonicalGenesis = input.GenesisSpan.ToArray();
        var genesis = MembershipContractCodec.DecodeGenesis(canonicalGenesis);
        if (!MembershipContractCodec.EncodeGenesis(genesis)
                .AsSpan()
                .SequenceEqual(canonicalGenesis) ||
            genesis.Policy.OfflineThreshold != 3 ||
            genesis.OfflineRoots.Count != 5 ||
            genesis.Policy.OnlineThreshold != 2 ||
            genesis.Policy.OnlineSignerCount != 3)
        {
            throw ProfileCarrierErrors.Verification();
        }

        var genesisApprovals = input.ApprovalValues
            .Select(ProfileCarrierAssemblyInput.CopySignature)
            .OrderBy(static value => value.SignerId, MemoryComparer.Instance)
            .ToArray();
        RequireExactSignatures(
            genesisApprovals,
            genesis.Policy.OfflineThreshold,
            MembershipSignatureDomain.Genesis);
        var genesisHash = MembershipContractHash.Sha256(canonicalGenesis);
        _ = MembershipContractVerifier.ImportSelfHostedGenesis(
            canonicalGenesis,
            genesis.NetworkId.Span,
            genesisHash,
            genesisApprovals,
            verifier);

        var delegationBytes = input.DelegationSpan.ToArray();
        var delegation = MembershipContractCodec.DecodeSignedDelegation(delegationBytes);
        RequireExactSignatures(
            delegation.Signatures,
            genesis.Policy.OfflineThreshold,
            MembershipSignatureDomain.OfflineDelegation);
        var genesisLastKnownGood = new MembershipLastKnownGood
        {
            NetworkId = genesis.NetworkId.ToArray(),
            PolicyVersion = genesis.PolicyVersion,
            Sequence = genesis.GenesisSequence,
            CanonicalHash = genesisHash
        };
        var verifiedDelegation = MembershipContractVerifier.VerifyDelegation(
            delegation,
            genesis,
            genesisLastKnownGood,
            options.VerificationTimeUnixSeconds,
            options.AllowedClockSkewSeconds,
            options.Protocol,
            verifier);

        if (input.BridgeValues.Count == 0)
        {
            throw ProfileCarrierErrors.InvalidInput();
        }
        var bridges = input.BridgeValues
            .Select(static bytes => new DecodedBridge(
                bytes.ToArray(),
                MembershipContractCodec.DecodeSignedBridge(bytes)))
            .OrderBy(static value => value.Signed.Statement.Sequence)
            .ThenBy(static value => value.Canonical, MemoryComparer.Instance)
            .ToArray();
        if (bridges.Select(static value => Convert.ToHexString(value.Canonical))
                .Distinct(StringComparer.Ordinal)
                .Count() != bridges.Length)
        {
            throw ProfileCarrierErrors.Verification();
        }

        var lastKnownGood = genesisLastKnownGood;
        foreach (var bridge in bridges)
        {
            RequireExactSignatures(
                bridge.Signed.Signatures,
                genesis.Policy.OnlineThreshold,
                MembershipSignatureDomain.Bridge);
            var context = new MembershipVerificationContext
            {
                Genesis = genesis,
                ActiveDelegation = delegation,
                AuthorityLastKnownGood = verifiedDelegation.NextAuthorityLastKnownGood,
                RevokedDelegationHashes = [],
                LastKnownGood = lastKnownGood,
                VerificationTimeUnixSeconds = options.VerificationTimeUnixSeconds,
                AllowedClockSkewSeconds = options.AllowedClockSkewSeconds,
                ClientProtocol = options.Protocol
            };
            lastKnownGood = MembershipContractVerifier.VerifyBridge(
                bridge.Signed,
                context,
                verifier).NextLastKnownGood;
        }

        var components = new List<ProfileComponent>(3 + bridges.Length)
        {
            new(ProfileComponentKind.CanonicalGenesis, canonicalGenesis),
            new(ProfileComponentKind.GenesisApprovals, EncodeGenesisApprovals(genesisApprovals)),
            new(ProfileComponentKind.SignedDelegation, delegationBytes)
        };
        components.AddRange(bridges.Select(static value =>
            new ProfileComponent(ProfileComponentKind.SignedBridge, value.Canonical)));

        var filePayload = ProfileCarrierFraming.Encode(components);
        return new(
            filePayload,
            SHA256.HashData(filePayload),
            $"sha256:{Convert.ToHexString(genesisHash).ToLowerInvariant()}",
            genesis.MinimumProtocol,
            genesis.MaximumProtocol,
            components.Count,
            bridges.Length);
    }

    internal static byte[] EncodeGenesisApprovals(
        IReadOnlyList<MembershipSignature> signatures)
    {
        var estimatedLength = 1 + signatures.Sum(static signature =>
            1 + MembershipLimits.SignerIdLength + 2 + signature.Signature.Length);
        var writer = new ArrayBufferWriter<byte>(estimatedLength);
        WriteByte(writer, checked((byte)signatures.Count));
        foreach (var signature in signatures
                     .OrderBy(static value => value.SignerId, MemoryComparer.Instance))
        {
            WriteByte(writer, (byte)signature.Domain);
            Write(writer, signature.SignerId.Span);
            WriteVarUInt(writer, checked((uint)signature.Signature.Length));
            Write(writer, signature.Signature.Span);
        }
        return writer.WrittenSpan.ToArray();
    }

    internal static IReadOnlyList<MembershipSignature> DecodeGenesisApprovals(
        ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length is 0 or > ProfileCarrierLimits.MaximumComponentBytes)
        {
            throw ProfileCarrierErrors.Framing();
        }
        var offset = 0;
        var count = encoded[offset++];
        if (count == 0 || count > MembershipLimits.MaximumSigners)
        {
            throw ProfileCarrierErrors.Framing();
        }

        var result = new MembershipSignature[count];
        ReadOnlySpan<byte> previousSigner = default;
        for (var index = 0; index < count; index++)
        {
            if (encoded.Length - offset < 1 + MembershipLimits.SignerIdLength)
            {
                throw ProfileCarrierErrors.Framing();
            }
            var domain = (MembershipSignatureDomain)encoded[offset++];
            if (!Enum.IsDefined(domain))
            {
                throw ProfileCarrierErrors.Framing();
            }
            var signerId = encoded.Slice(offset, MembershipLimits.SignerIdLength);
            offset += MembershipLimits.SignerIdLength;
            if (index > 0 && MemoryComparer.Compare(previousSigner, signerId) >= 0)
            {
                throw ProfileCarrierErrors.Framing();
            }
            var signatureLength = ReadVarUInt(encoded, ref offset);
            if (signatureLength is < MembershipLimits.MinimumSignatureLength
                or > MembershipLimits.MaximumSignatureLength ||
                encoded.Length - offset < signatureLength)
            {
                throw ProfileCarrierErrors.Framing();
            }
            result[index] = new MembershipSignature
            {
                SignerId = signerId.ToArray(),
                Domain = domain,
                Signature = encoded.Slice(offset, signatureLength).ToArray()
            };
            offset += signatureLength;
            previousSigner = signerId;
        }
        if (offset != encoded.Length)
        {
            throw ProfileCarrierErrors.Framing();
        }
        return result;
    }

    private static void RequireExactSignatures(
        IReadOnlyList<MembershipSignature> signatures,
        int exactCount,
        MembershipSignatureDomain domain)
    {
        if (signatures is null ||
            signatures.Count != exactCount ||
            signatures.Any(signature =>
                signature is null ||
                signature.Domain != domain ||
                signature.SignerId.Length != MembershipLimits.SignerIdLength ||
                signature.Signature.Length is < MembershipLimits.MinimumSignatureLength
                    or > MembershipLimits.MaximumSignatureLength) ||
            signatures.Select(static signature => Convert.ToHexString(signature.SignerId.Span))
                .Distinct(StringComparer.Ordinal)
                .Count() != exactCount)
        {
            throw ProfileCarrierErrors.Verification();
        }
    }

    private static int ReadVarUInt(ReadOnlySpan<byte> source, ref int offset)
    {
        uint value = 0;
        var shift = 0;
        var count = 0;
        while (true)
        {
            if (offset >= source.Length || count == 5)
            {
                throw ProfileCarrierErrors.Framing();
            }
            var current = source[offset++];
            count++;
            if (count == 5 && (current & 0xf0) != 0)
            {
                throw ProfileCarrierErrors.Framing();
            }
            value |= (uint)(current & 0x7f) << shift;
            if ((current & 0x80) == 0)
            {
                if (count != VarUIntLength(value) || value > int.MaxValue)
                {
                    throw ProfileCarrierErrors.Framing();
                }
                return (int)value;
            }
            shift += 7;
        }
    }

    private static int VarUIntLength(uint value)
    {
        var length = 1;
        while (value >= 0x80)
        {
            value >>= 7;
            length++;
        }
        return length;
    }

    private static void WriteVarUInt(IBufferWriter<byte> writer, uint value)
    {
        do
        {
            var next = (byte)(value & 0x7f);
            value >>= 7;
            if (value != 0)
            {
                next |= 0x80;
            }
            WriteByte(writer, next);
        } while (value != 0);
    }

    private static void WriteByte(IBufferWriter<byte> writer, byte value)
    {
        var span = writer.GetSpan(1);
        span[0] = value;
        writer.Advance(1);
    }

    private static void Write(IBufferWriter<byte> writer, ReadOnlySpan<byte> value)
    {
        value.CopyTo(writer.GetSpan(value.Length));
        writer.Advance(value.Length);
    }

    private sealed record DecodedBridge(byte[] Canonical, SignedBridgeSnapshot Signed);

    private sealed class MemoryComparer :
        IComparer<ReadOnlyMemory<byte>>,
        IComparer<byte[]>
    {
        public static MemoryComparer Instance { get; } = new();

        public int Compare(ReadOnlyMemory<byte> x, ReadOnlyMemory<byte> y) =>
            Compare(x.Span, y.Span);

        public int Compare(byte[]? x, byte[]? y) =>
            Compare((x ?? []).AsSpan(), (y ?? []).AsSpan());

        public static int Compare(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y) =>
            x.SequenceCompareTo(y);
    }
}
