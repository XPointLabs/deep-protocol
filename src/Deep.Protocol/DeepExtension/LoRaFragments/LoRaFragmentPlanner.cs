using System.Buffers.Binary;
using Deep.Protocol.DeepExtension.OpaqueBundles;

namespace Deep.Protocol.DeepExtension.LoRaFragments;

public static class LoRaFragmentPlanner
{
    public static LoRaFragmentPlan Plan(
        LoRaFragmentPlanRequest request,
        LoRaFragmentPolicy policy,
        ILoRaFragmentAuthenticator authenticator)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(authenticator);

        ValidateRequestAgainstPolicy(request, policy);

        OpaqueBundle opaqueBundle;
        try
        {
            opaqueBundle = OpaqueBundleCodec.Decode(
                request.EncodedOpaqueBundleSpan,
                policy.OpaqueBundleDecodePolicy);
        }
        catch (OpaqueBundleException exception)
        {
            throw new LoRaFragmentException(
                LoRaFragmentError.OpaqueBundleRejected,
                $"The exact encoded opaque bundle was rejected: {exception.Error}.",
                exception);
        }

        if (opaqueBundle.WireVersion !=
            Deep.Protocol.DeepExtension.OpaqueBundles.OpaqueBundleWireVersion.V1)
        {
            throw Error(
                LoRaFragmentError.OpaqueBundleRejected,
                "Only an accepted DPB1 V1 opaque bundle may be fragmented.");
        }

        var bundleLength = request.EncodedOpaqueBundleSpan.Length;
        var describedLength = checked(LoRaFragmentLimits.DescriptorLength + bundleLength);
        var dataShardCount = checked(
            (describedLength + request.ShardSize - 1) / request.ShardSize);
        if (dataShardCount is < LoRaFragmentLimits.MinimumDataShardCount
            or > LoRaFragmentLimits.MaximumDataShardCount)
        {
            throw Error(
                LoRaFragmentError.InvalidDataShardCount,
                "The selected shard size cannot represent this bundle within the absolute data-shard bound.");
        }

        if (dataShardCount > policy.MaxDataShards)
        {
            throw Error(
                LoRaFragmentError.PolicyRejected,
                "The planned data-shard count exceeds the caller's lower ceiling.");
        }

        var parityShardCount = request.FecMode switch
        {
            LoRaFragmentFecMode.None => 0,
            LoRaFragmentFecMode.Xor1 =>
                (dataShardCount + LoRaFragmentLimits.XorDataShardsPerGroup - 1) /
                LoRaFragmentLimits.XorDataShardsPerGroup,
            _ => throw Error(
                LoRaFragmentError.InvalidFec,
                "The requested FEC mode is not implemented by V1.")
        };
        if (parityShardCount > LoRaFragmentLimits.MaximumParityShardCount)
        {
            throw Error(
                LoRaFragmentError.InvalidParityShardCount,
                "The planned parity-shard count exceeds the absolute V1 bound.");
        }

        if (parityShardCount > policy.MaxParityShards)
        {
            throw Error(
                LoRaFragmentError.PolicyRejected,
                "The planned parity-shard count exceeds the caller's lower ceiling.");
        }

        var reservedDataShardBytes = checked(dataShardCount * request.ShardSize);
        if (reservedDataShardBytes > LoRaFragmentLimits.MaximumReservedDataShardBytes)
        {
            throw Error(
                LoRaFragmentError.PolicyRejected,
                "The planned data shards exceed the absolute per-message reservation bound.");
        }

        var descriptor = new LoRaFragmentDescriptor(
            request.CurrentHop,
            request.HopLimit,
            checked((ushort)bundleLength),
            opaqueBundle.ExpiryBucket);
        var paddedData = new byte[reservedDataShardBytes];
        WriteDescriptor(descriptor, paddedData);
        request.EncodedOpaqueBundleSpan.CopyTo(
            paddedData.AsSpan(LoRaFragmentLimits.DescriptorLength));

        var totalFragmentCount = checked(dataShardCount + parityShardCount);
        if (totalFragmentCount > LoRaFragmentLimits.MaximumTotalFragmentCount)
        {
            throw Error(
                LoRaFragmentError.PolicyRejected,
                "The planned total fragment count exceeds the absolute V1 bound.");
        }

        var encodedFrames = new List<ReadOnlyMemory<byte>>(totalFragmentCount);
        for (var dataIndex = 0; dataIndex < dataShardCount; dataIndex++)
        {
            var shard = paddedData.AsSpan(
                checked(dataIndex * request.ShardSize),
                request.ShardSize);
            encodedFrames.Add(EncodeFrame(
                request,
                checked((byte)dataIndex),
                checked((byte)dataShardCount),
                checked((byte)parityShardCount),
                shard,
                authenticator));
        }

        for (var groupIndex = 0; groupIndex < parityShardCount; groupIndex++)
        {
            var parityShard = CreateXorParityShard(
                paddedData,
                dataShardCount,
                request.ShardSize,
                groupIndex);
            encodedFrames.Add(EncodeFrame(
                request,
                checked((byte)(dataShardCount + groupIndex)),
                checked((byte)dataShardCount),
                checked((byte)parityShardCount),
                parityShard,
                authenticator));
        }

        return new LoRaFragmentPlan(
            encodedFrames,
            checked((byte)dataShardCount),
            checked((byte)parityShardCount),
            descriptor);
    }

    private static void ValidateRequestAgainstPolicy(
        LoRaFragmentPlanRequest request,
        LoRaFragmentPolicy policy)
    {
        if (request.EncodedOpaqueBundleSpan.Length > policy.MaxBundleLength)
        {
            throw Error(
                LoRaFragmentError.PolicyRejected,
                "The encoded opaque bundle exceeds the caller's lower bundle-length ceiling.");
        }

        if (request.ShardSize < policy.MinimumShardSize ||
            request.ShardSize > policy.MaxShardSize)
        {
            throw Error(
                LoRaFragmentError.PolicyRejected,
                "The requested shard size is outside the caller's narrowed range.");
        }
    }

    private static void WriteDescriptor(
        LoRaFragmentDescriptor descriptor,
        Span<byte> destination)
    {
        if (destination.Length < LoRaFragmentLimits.DescriptorLength)
        {
            throw new ArgumentException(
                "The descriptor destination is too short.",
                nameof(destination));
        }

        destination[0] = LoRaFragmentLimits.DescriptorVersion;
        destination[1] = LoRaFragmentLimits.OpaqueBundlePayloadKind;
        destination[2] = LoRaFragmentLimits.OpaqueBundleWireVersion;
        destination[3] = (byte)((descriptor.CurrentHop << 4) | descriptor.HopLimit);
        BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(4, 2), descriptor.BundleLength);
        BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(6, 4), descriptor.ExpiryBucket);
    }

    private static byte[] EncodeFrame(
        LoRaFragmentPlanRequest request,
        byte ordinal,
        byte dataShardCount,
        byte parityShardCount,
        ReadOnlySpan<byte> shard,
        ILoRaFragmentAuthenticator authenticator)
    {
        var header = new LoRaFragmentHeader(
            request.MessageIdSpan,
            ordinal,
            dataShardCount,
            parityShardCount,
            request.ShardSize,
            request.FecMode);
        var unsignedFrame = new LoRaFragmentUnsignedFrame(header, shard);
        return LoRaFragmentCodec.Encode(
            unsignedFrame,
            request.AuthenticationHandle,
            request.Direction,
            authenticator);
    }

    private static byte[] CreateXorParityShard(
        ReadOnlySpan<byte> paddedData,
        int dataShardCount,
        int shardSize,
        int groupIndex)
    {
        var parity = new byte[shardSize];
        var firstDataIndex = checked(groupIndex * LoRaFragmentLimits.XorDataShardsPerGroup);
        var exclusiveEnd = Math.Min(
            dataShardCount,
            checked(firstDataIndex + LoRaFragmentLimits.XorDataShardsPerGroup));
        for (var dataIndex = firstDataIndex; dataIndex < exclusiveEnd; dataIndex++)
        {
            var shard = paddedData.Slice(checked(dataIndex * shardSize), shardSize);
            for (var byteIndex = 0; byteIndex < shardSize; byteIndex++)
            {
                parity[byteIndex] ^= shard[byteIndex];
            }
        }

        return parity;
    }

    private static LoRaFragmentException Error(
        LoRaFragmentError error,
        string message) =>
        new(error, message);
}
