using Deep.Protocol.DeepExtension.OpaqueBundles;

namespace Deep.Protocol.DeepExtension.LoRaFragments;

public static class LoRaFragmentDomains
{
    public static ReadOnlySpan<byte> Authentication => "Deep/P18A/LoRaFragmentAuth/v1"u8;
}

public static class LoRaFragmentLimits
{
    public const int HeaderLength = 16;
    public const int DescriptorLength = 10;
    public const int AuthenticationTagLength = 16;
    public const int MessageIdLength = 8;
    public const int MinimumShardSize = 8;
    public const int MaximumShardSize = 192;
    public const int MinimumEncodedFrameLength =
        HeaderLength + MinimumShardSize + AuthenticationTagLength;
    public const int MaximumEncodedFrameLength =
        HeaderLength + MaximumShardSize + AuthenticationTagLength;
    public const int MinimumBundleLength = 64;
    public const int MaximumBundleLength = 4096;
    public const int MinimumDataShardCount = 1;
    public const int MaximumDataShardCount = 64;
    public const int MaximumParityShardCount = 8;
    public const int MaximumTotalFragmentCount =
        MaximumDataShardCount + MaximumParityShardCount;
    public const int XorDataShardsPerGroup = 8;
    public const int MaximumReservedDataShardBytes = 4352;
    public const byte WireVersion = 1;
    public const byte DescriptorVersion = 1;
    public const byte OpaqueBundlePayloadKind = 1;
    public const byte OpaqueBundleWireVersion = 1;
}

public enum LoRaFragmentFecMode : byte
{
    None = 0,
    Xor1 = 1
}

public enum LoRaFragmentDirection : byte
{
    Forward = 1,
    Reverse = 2
}

public enum LoRaFragmentError
{
    None = 0,
    EncodedLengthOutOfRange,
    InvalidMagic,
    UnsupportedVersion,
    UnknownFlags,
    InvalidMessageId,
    InvalidOrdinal,
    InvalidDataShardCount,
    InvalidParityShardCount,
    InvalidShardSize,
    InvalidAuthenticationTag,
    AuthenticationFailed,
    InvalidDescriptor,
    InvalidHop,
    InvalidBundleLength,
    NonCanonicalDataShardCount,
    NonCanonicalPadding,
    OpaqueBundleRejected,
    ExpiryMismatch,
    InvalidFec,
    PolicyRejected
}

public sealed class LoRaFragmentAuthenticationHandle
{
    internal LoRaFragmentAuthenticationHandle() { }
}

public interface ILoRaFragmentAuthenticationHandleProvider
{
    LoRaFragmentAuthenticationHandle GetAuthenticationHandle();
}

public abstract class LoRaFragmentAuthenticationHandleProviderBase
    : ILoRaFragmentAuthenticationHandleProvider
{
    public abstract LoRaFragmentAuthenticationHandle GetAuthenticationHandle();

    protected static LoRaFragmentAuthenticationHandle CreateOpaqueAuthenticationHandle() => new();
}

public sealed class LoRaFragmentReplayScopeHandle
{
    internal LoRaFragmentReplayScopeHandle() { }
}

public interface ILoRaFragmentReplayScopeHandleProvider
{
    LoRaFragmentReplayScopeHandle GetReplayScopeHandle();
}

public abstract class LoRaFragmentReplayScopeHandleProviderBase
    : ILoRaFragmentReplayScopeHandleProvider
{
    public abstract LoRaFragmentReplayScopeHandle GetReplayScopeHandle();

    protected static LoRaFragmentReplayScopeHandle CreateOpaqueReplayScopeHandle() => new();
}

public interface ILoRaFragmentAuthenticator
{
    byte[] CreateTag(
        ReadOnlySpan<byte> domain,
        LoRaFragmentAuthenticationHandle authenticationHandle,
        LoRaFragmentDirection direction,
        ReadOnlySpan<byte> canonicalTranscript);

    bool VerifyTag(
        ReadOnlySpan<byte> domain,
        LoRaFragmentAuthenticationHandle authenticationHandle,
        LoRaFragmentDirection direction,
        ReadOnlySpan<byte> canonicalTranscript,
        ReadOnlySpan<byte> authenticationTag);
}

public sealed class LoRaFragmentPolicy
{
    public LoRaFragmentPolicy(
        OpaqueBundleDecodePolicy opaqueBundleDecodePolicy,
        int maxBundleLength = LoRaFragmentLimits.MaximumBundleLength,
        int maxDataShards = LoRaFragmentLimits.MaximumDataShardCount,
        int maxParityShards = LoRaFragmentLimits.MaximumParityShardCount,
        int maxShardSize = LoRaFragmentLimits.MaximumShardSize,
        int minimumShardSize = LoRaFragmentLimits.MinimumShardSize)
    {
        ArgumentNullException.ThrowIfNull(opaqueBundleDecodePolicy);

        if (maxBundleLength is < LoRaFragmentLimits.MinimumBundleLength
            or > LoRaFragmentLimits.MaximumBundleLength)
        {
            throw new ArgumentOutOfRangeException(nameof(maxBundleLength));
        }

        if (maxDataShards is < LoRaFragmentLimits.MinimumDataShardCount
            or > LoRaFragmentLimits.MaximumDataShardCount)
        {
            throw new ArgumentOutOfRangeException(nameof(maxDataShards));
        }

        if (maxParityShards is < 0 or > LoRaFragmentLimits.MaximumParityShardCount)
        {
            throw new ArgumentOutOfRangeException(nameof(maxParityShards));
        }

        if (maxShardSize is < LoRaFragmentLimits.MinimumShardSize
            or > LoRaFragmentLimits.MaximumShardSize)
        {
            throw new ArgumentOutOfRangeException(nameof(maxShardSize));
        }

        if (minimumShardSize is < LoRaFragmentLimits.MinimumShardSize
            or > LoRaFragmentLimits.MaximumShardSize ||
            minimumShardSize > maxShardSize)
        {
            throw new ArgumentOutOfRangeException(nameof(minimumShardSize));
        }

        OpaqueBundleDecodePolicy = opaqueBundleDecodePolicy with { };
        MaxBundleLength = maxBundleLength;
        MaxDataShards = maxDataShards;
        MaxParityShards = maxParityShards;
        MaxShardSize = maxShardSize;
        MinimumShardSize = minimumShardSize;
    }

    public OpaqueBundleDecodePolicy OpaqueBundleDecodePolicy { get; }
    public int MaxBundleLength { get; }
    public int MaxDataShards { get; }
    public int MaxParityShards { get; }
    public int MaxShardSize { get; }
    public int MinimumShardSize { get; }
}

public sealed class LoRaFragmentHeader
{
    private readonly byte[] _messageId;

    public LoRaFragmentHeader(
        ReadOnlySpan<byte> messageId,
        byte ordinal,
        byte dataShardCount,
        byte parityShardCount,
        byte shardSize,
        LoRaFragmentFecMode fecMode)
    {
        if (messageId.Length != LoRaFragmentLimits.MessageIdLength ||
            messageId.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "The hop-local message ID must contain exactly eight non-all-zero opaque bytes.",
                nameof(messageId));
        }

        if (dataShardCount is < LoRaFragmentLimits.MinimumDataShardCount
            or > LoRaFragmentLimits.MaximumDataShardCount)
        {
            throw new ArgumentOutOfRangeException(nameof(dataShardCount));
        }

        if (shardSize is < LoRaFragmentLimits.MinimumShardSize
            or > LoRaFragmentLimits.MaximumShardSize)
        {
            throw new ArgumentOutOfRangeException(nameof(shardSize));
        }

        var expectedParityCount = fecMode switch
        {
            LoRaFragmentFecMode.None => 0,
            LoRaFragmentFecMode.Xor1 =>
                (dataShardCount + LoRaFragmentLimits.XorDataShardsPerGroup - 1) /
                LoRaFragmentLimits.XorDataShardsPerGroup,
            _ => throw new ArgumentOutOfRangeException(nameof(fecMode))
        };

        if (parityShardCount != expectedParityCount ||
            parityShardCount > LoRaFragmentLimits.MaximumParityShardCount)
        {
            throw new ArgumentOutOfRangeException(
                nameof(parityShardCount),
                "The parity count is not canonical for the selected FEC mode.");
        }

        var totalFragmentCount = checked(dataShardCount + parityShardCount);
        if (totalFragmentCount > LoRaFragmentLimits.MaximumTotalFragmentCount ||
            ordinal >= totalFragmentCount)
        {
            throw new ArgumentOutOfRangeException(nameof(ordinal));
        }

        var dataCapacity = checked(dataShardCount * shardSize);
        if (dataCapacity > LoRaFragmentLimits.MaximumReservedDataShardBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(dataShardCount),
                "The declared data-shard reservation exceeds the absolute per-message ceiling.");
        }

        if (dataCapacity <
            LoRaFragmentLimits.DescriptorLength + LoRaFragmentLimits.MinimumBundleLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(dataShardCount),
                "The declared data shards cannot contain the descriptor and minimum V1 bundle.");
        }

        _messageId = messageId.ToArray();
        Ordinal = ordinal;
        DataShardCount = dataShardCount;
        ParityShardCount = parityShardCount;
        ShardSize = shardSize;
        FecMode = fecMode;
    }

    public ReadOnlyMemory<byte> MessageId => _messageId.ToArray();
    public byte Ordinal { get; }
    public byte DataShardCount { get; }
    public byte ParityShardCount { get; }
    public byte ShardSize { get; }
    public LoRaFragmentFecMode FecMode { get; }
    public int TotalFragmentCount => DataShardCount + ParityShardCount;

    internal ReadOnlySpan<byte> MessageIdSpan => _messageId;
}

public sealed class LoRaFragmentDescriptor
{
    public LoRaFragmentDescriptor(
        byte currentHop,
        byte hopLimit,
        ushort bundleLength,
        uint expiryBucket)
    {
        if (currentHop >= hopLimit || hopLimit > 15)
        {
            throw new ArgumentOutOfRangeException(
                nameof(currentHop),
                "The current hop must be less than a nonzero hop limit no greater than fifteen.");
        }

        if (bundleLength is < LoRaFragmentLimits.MinimumBundleLength
            or > LoRaFragmentLimits.MaximumBundleLength)
        {
            throw new ArgumentOutOfRangeException(nameof(bundleLength));
        }

        CurrentHop = currentHop;
        HopLimit = hopLimit;
        BundleLength = bundleLength;
        ExpiryBucket = expiryBucket;
    }

    public byte CurrentHop { get; }
    public byte HopLimit { get; }
    public ushort BundleLength { get; }
    public uint ExpiryBucket { get; }
}

public sealed class LoRaFragmentUnsignedFrame
{
    private readonly byte[] _shard;

    public LoRaFragmentUnsignedFrame(LoRaFragmentHeader header, ReadOnlySpan<byte> shard)
    {
        ArgumentNullException.ThrowIfNull(header);
        if (shard.Length != header.ShardSize)
        {
            throw new ArgumentException(
                "The shard must have the exact fixed size declared by the header.",
                nameof(shard));
        }

        Header = header;
        _shard = shard.ToArray();
    }

    public LoRaFragmentHeader Header { get; }
    public ReadOnlyMemory<byte> Shard => _shard.ToArray();

    internal ReadOnlySpan<byte> ShardSpan => _shard;
}

public sealed class LoRaFragmentFrame
{
    private readonly byte[] _shardStorage;
    private readonly int _shardOffset;
    private readonly byte[] _authenticationTag;

    public LoRaFragmentFrame(
        LoRaFragmentHeader header,
        ReadOnlySpan<byte> shard,
        ReadOnlySpan<byte> authenticationTag)
    {
        ArgumentNullException.ThrowIfNull(header);
        if (shard.Length != header.ShardSize)
        {
            throw new ArgumentException(
                "The shard must have the exact fixed size declared by the header.",
                nameof(shard));
        }

        if (authenticationTag.Length != LoRaFragmentLimits.AuthenticationTagLength)
        {
            throw new ArgumentException(
                "The authentication tag must contain exactly sixteen bytes.",
                nameof(authenticationTag));
        }

        Header = header;
        _shardStorage = shard.ToArray();
        _shardOffset = 0;
        _authenticationTag = authenticationTag.ToArray();
    }

    private LoRaFragmentFrame(
        LoRaFragmentHeader header,
        byte[] authenticatedTranscript,
        int shardOffset,
        byte[] authenticationTag)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(authenticatedTranscript);
        ArgumentNullException.ThrowIfNull(authenticationTag);
        if (shardOffset < 0 ||
            shardOffset > authenticatedTranscript.Length - header.ShardSize)
        {
            throw new ArgumentOutOfRangeException(nameof(shardOffset));
        }

        if (authenticationTag.Length != LoRaFragmentLimits.AuthenticationTagLength)
        {
            throw new ArgumentException(
                "The authentication tag must contain exactly sixteen bytes.",
                nameof(authenticationTag));
        }

        Header = header;
        _shardStorage = authenticatedTranscript;
        _shardOffset = shardOffset;
        _authenticationTag = authenticationTag;
    }

    internal static LoRaFragmentFrame FromAuthenticatedTranscript(
        LoRaFragmentHeader header,
        byte[] authenticatedTranscript,
        int shardOffset,
        byte[] authenticationTag) =>
        new(header, authenticatedTranscript, shardOffset, authenticationTag);

    public LoRaFragmentHeader Header { get; }
    public ReadOnlyMemory<byte> Shard => ShardSpan.ToArray();
    public ReadOnlyMemory<byte> AuthenticationTag => _authenticationTag.ToArray();

    internal ReadOnlySpan<byte> ShardSpan =>
        _shardStorage.AsSpan(_shardOffset, Header.ShardSize);
    internal ReadOnlySpan<byte> AuthenticationTagSpan => _authenticationTag;
}

public sealed class LoRaFragmentPlanRequest
{
    private readonly byte[] _encodedOpaqueBundle;
    private readonly byte[] _messageId;

    public LoRaFragmentPlanRequest(
        ReadOnlySpan<byte> encodedOpaqueBundle,
        ReadOnlySpan<byte> messageId,
        byte currentHop,
        byte hopLimit,
        byte shardSize,
        LoRaFragmentFecMode fecMode,
        LoRaFragmentDirection direction,
        LoRaFragmentAuthenticationHandle authenticationHandle)
    {
        if (encodedOpaqueBundle.Length is < LoRaFragmentLimits.MinimumBundleLength
            or > LoRaFragmentLimits.MaximumBundleLength)
        {
            throw new ArgumentOutOfRangeException(nameof(encodedOpaqueBundle));
        }

        if (messageId.Length != LoRaFragmentLimits.MessageIdLength ||
            messageId.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "The hop-local message ID must contain exactly eight non-all-zero opaque bytes.",
                nameof(messageId));
        }

        if (currentHop >= hopLimit || hopLimit > 15)
        {
            throw new ArgumentOutOfRangeException(nameof(currentHop));
        }

        if (shardSize is < LoRaFragmentLimits.MinimumShardSize
            or > LoRaFragmentLimits.MaximumShardSize)
        {
            throw new ArgumentOutOfRangeException(nameof(shardSize));
        }

        if (fecMode is not LoRaFragmentFecMode.None and not LoRaFragmentFecMode.Xor1)
        {
            throw new ArgumentOutOfRangeException(nameof(fecMode));
        }

        if (direction is not LoRaFragmentDirection.Forward and not LoRaFragmentDirection.Reverse)
        {
            throw new ArgumentOutOfRangeException(nameof(direction));
        }

        ArgumentNullException.ThrowIfNull(authenticationHandle);

        _encodedOpaqueBundle = encodedOpaqueBundle.ToArray();
        _messageId = messageId.ToArray();
        CurrentHop = currentHop;
        HopLimit = hopLimit;
        ShardSize = shardSize;
        FecMode = fecMode;
        Direction = direction;
        AuthenticationHandle = authenticationHandle;
    }

    public ReadOnlyMemory<byte> EncodedOpaqueBundle => _encodedOpaqueBundle.ToArray();
    public ReadOnlyMemory<byte> MessageId => _messageId.ToArray();
    public byte CurrentHop { get; }
    public byte HopLimit { get; }
    public byte ShardSize { get; }
    public LoRaFragmentFecMode FecMode { get; }
    public LoRaFragmentDirection Direction { get; }
    public LoRaFragmentAuthenticationHandle AuthenticationHandle { get; }

    internal ReadOnlySpan<byte> EncodedOpaqueBundleSpan => _encodedOpaqueBundle;
    internal ReadOnlySpan<byte> MessageIdSpan => _messageId;
}

public sealed class LoRaFragmentPlan
{
    private readonly byte[][] _frames;

    internal LoRaFragmentPlan(
        IEnumerable<ReadOnlyMemory<byte>> frames,
        byte dataShardCount,
        byte parityShardCount,
        LoRaFragmentDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(frames);
        ArgumentNullException.ThrowIfNull(descriptor);

        if (dataShardCount is < LoRaFragmentLimits.MinimumDataShardCount
            or > LoRaFragmentLimits.MaximumDataShardCount)
        {
            throw new ArgumentOutOfRangeException(nameof(dataShardCount));
        }

        var canonicalXorParityCount =
            (dataShardCount + LoRaFragmentLimits.XorDataShardsPerGroup - 1) /
            LoRaFragmentLimits.XorDataShardsPerGroup;
        if (parityShardCount != 0 && parityShardCount != canonicalXorParityCount)
        {
            throw new ArgumentOutOfRangeException(nameof(parityShardCount));
        }

        var expectedFrameCount = checked(dataShardCount + parityShardCount);
        if (expectedFrameCount > LoRaFragmentLimits.MaximumTotalFragmentCount)
        {
            throw new ArgumentOutOfRangeException(nameof(parityShardCount));
        }

        var boundedFrames = new List<byte[]>(expectedFrameCount);
        foreach (var frame in frames)
        {
            if (boundedFrames.Count == expectedFrameCount)
            {
                throw new ArgumentException(
                    "The encoded frame collection contains more frames than declared.",
                    nameof(frames));
            }

            if (frame.Length is < LoRaFragmentLimits.MinimumEncodedFrameLength
                or > LoRaFragmentLimits.MaximumEncodedFrameLength)
            {
                throw new ArgumentException(
                    "Every encoded frame must remain within the absolute V1 frame bounds.",
                    nameof(frames));
            }

            boundedFrames.Add(frame.ToArray());
        }

        if (boundedFrames.Count != expectedFrameCount)
        {
            throw new ArgumentException(
                "The encoded frame collection must match the declared data and parity counts.",
                nameof(frames));
        }

        _frames = boundedFrames.ToArray();
        DataShardCount = dataShardCount;
        ParityShardCount = parityShardCount;
        Descriptor = descriptor;
    }

    public IReadOnlyList<ReadOnlyMemory<byte>> Frames =>
        _frames.Select(static frame => (ReadOnlyMemory<byte>)frame.ToArray()).ToArray();
    public byte DataShardCount { get; }
    public byte ParityShardCount { get; }
    public LoRaFragmentDescriptor Descriptor { get; }
}

public sealed class LoRaFragmentException : Exception
{
    public LoRaFragmentException(
        LoRaFragmentError error,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        Error = error;
    }

    public LoRaFragmentError Error { get; }
}
